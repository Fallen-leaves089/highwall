use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::{JoinError, JoinHandle, JoinSet},
    time::{timeout, Instant},
};
use tokio_rustls::server::TlsStream;

use crate::{
    audit::{next_request_id, AuditEvent},
    config::{AppConfig, ProxyProtocolMode},
    error::{CoreError, Result},
    h1_server, h2_server, h3_server,
    limits::{ConnectionGuard, PendingConnectionGuard},
    proxy_protocol,
    state::AppState,
    tls::TlsConnectionInfo,
};

const RULE_HANDSHAKE_RATE: &str = "HW-NATIVE-TLS-RATE-001";
const RULE_TLS_PROTOCOL: &str = "HW-NATIVE-TLS-001";
const RULE_QUIC_PROTOCOL: &str = "HW-NATIVE-QUIC-001";
const RULE_QUIC_ACL: &str = "HW-NATIVE-QUIC-ACL-001";
const RULE_CONNECTION_BUDGET: &str = "HW-NATIVE-CONN-001";
const RULE_PROXY_PROTOCOL: &str = "HW-NATIVE-PROXY-001";
const ACCEPT_RETRY_INITIAL: Duration = Duration::from_millis(50);
const ACCEPT_RETRY_MAX: Duration = Duration::from_secs(1);

pub async fn run(config: AppConfig) -> Result<()> {
    config.validate()?;
    let state = AppState::new(config).await?;
    let listen = SocketAddr::new(state.config.listen.host, state.config.listen.port);
    let listener = TcpListener::bind(listen).await.map_err(|error| {
        CoreError::Config(format!("cannot bind TCP listener {listen}: {error}"))
    })?;
    let tcp_local = listener.local_addr().map_err(CoreError::Io)?;
    tracing::info!(address = %tcp_local, tls = state.tls.is_some(), "native TCP listener ready");

    let quic_endpoint = build_quic_endpoint(&state)?;
    if let Some(endpoint) = &quic_endpoint {
        let local = endpoint.local_addr().map_err(|error| {
            CoreError::Config(format!("cannot read QUIC local address: {error}"))
        })?;
        tracing::info!(address = %local, "native QUIC listener ready");
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let tcp_state = state.clone();
    let tcp_shutdown = shutdown_rx.clone();
    let mut tcp_task =
        tokio::spawn(async move { tcp_accept_loop(listener, tcp_state, tcp_shutdown).await });
    let quic_state = state.clone();
    let quic_shutdown = shutdown_rx;
    let mut quic_task =
        tokio::spawn(
            async move { quic_accept_loop(quic_endpoint, quic_state, quic_shutdown).await },
        );

    enum Exit {
        Signal,
        Tcp(std::result::Result<Result<()>, JoinError>),
        Quic(std::result::Result<Result<()>, JoinError>),
    }

    let exit = tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            if let Err(error) = signal {
                tracing::error!(error = %error, "failed to listen for shutdown signal");
            }
            Exit::Signal
        }
        result = &mut tcp_task => Exit::Tcp(result),
        result = &mut quic_task => Exit::Quic(result),
    };
    let _ = shutdown_tx.send(true);

    let final_result = match exit {
        Exit::Signal => {
            let tcp = finish_task(tcp_task, "TCP listener").await;
            let quic = finish_task(quic_task, "QUIC listener").await;
            tcp.and(quic)
        }
        Exit::Tcp(result) => {
            let tcp = unexpected_task_result(result, "TCP listener");
            let quic = finish_task(quic_task, "QUIC listener").await;
            tcp.and(quic)
        }
        Exit::Quic(result) => {
            let quic = unexpected_task_result(result, "QUIC listener");
            let tcp = finish_task(tcp_task, "TCP listener").await;
            quic.and(tcp)
        }
    };
    final_result
}

fn build_quic_endpoint(state: &AppState) -> Result<Option<quinn::Endpoint>> {
    let Some(quic) = state.config.quic.as_ref().filter(|quic| quic.enabled) else {
        return Ok(None);
    };
    let crypto = state
        .tls
        .as_ref()
        .and_then(|bundle| bundle.quic_crypto.as_deref())
        .ok_or_else(|| {
            CoreError::Config("QUIC is enabled without a QUIC TLS bundle".to_string())
        })?;
    let server_config = h3_server::build_quic_server_config(quic, crypto)?;
    let address = SocketAddr::new(quic.effective_host(&state.config.listen), quic.listen_port);
    let socket = std::net::UdpSocket::bind(address).map_err(|error| {
        CoreError::Config(format!("cannot bind QUIC socket {address}: {error}"))
    })?;
    socket.set_nonblocking(true).map_err(|error| {
        CoreError::Config(format!("cannot make QUIC socket nonblocking: {error}"))
    })?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config
        .max_udp_payload_size(quic.max_udp_payload_size)
        .map_err(|error| CoreError::Config(format!("invalid QUIC UDP payload limit: {error}")))?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| CoreError::Config("no QUIC async runtime is available".to_string()))?;
    quinn::Endpoint::new(endpoint_config, Some(server_config), socket, runtime)
        .map(Some)
        .map_err(|error| CoreError::Config(format!("cannot create QUIC endpoint: {error}")))
}

async fn tcp_accept_loop(
    listener: TcpListener,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let mut retry_at: Option<Instant> = None;
    let mut accept_backoff = ACCEPT_RETRY_INITIAL;
    loop {
        let retry_deadline = retry_at;
        let retry_wait = async move {
            match retry_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::warn!(error = %error, "TCP connection task failed");
                }
            }
            _ = retry_wait, if retry_at.is_some() => {
                retry_at = None;
            }
            accepted = listener.accept(), if retry_at.is_none() => {
                let (stream, peer) = match accepted {
                    Ok(value) => {
                        accept_backoff = ACCEPT_RETRY_INITIAL;
                        value
                    }
                    Err(error) => {
                        if *shutdown.borrow() {
                            break;
                        }
                        if !is_transient_accept_error(&error) {
                            return Err(CoreError::Io(error));
                        }
                        let delay = accept_backoff;
                        accept_backoff = next_accept_backoff(accept_backoff);
                        tracing::warn!(
                            error = %error,
                            retry_in_ms = delay.as_millis(),
                            "transient TCP accept error; retrying"
                        );
                        retry_at = Some(Instant::now() + delay);
                        continue;
                    }
                };
                let proxy = &state.config.listen.proxy_protocol;
                if proxy.mode != ProxyProtocolMode::Off && proxy.trusts(peer.ip()) {
                    let Some(pending) = state.connections.try_acquire_pending() else {
                        record_transport_reject(
                            &state,
                            peer,
                            "tcp",
                            RULE_CONNECTION_BUDGET,
                            "connection budget is exhausted",
                        );
                        drop(stream);
                        continue;
                    };
                    let _ = stream.set_nodelay(true);
                    let task_state = state.clone();
                    let task_shutdown = shutdown.clone();
                    tasks.spawn(async move {
                        handle_proxied_tcp_connection(
                            stream,
                            peer,
                            pending,
                            task_state,
                            task_shutdown,
                        )
                        .await;
                    });
                    continue;
                }
                if proxy.mode == ProxyProtocolMode::Required {
                    record_transport_reject(
                        &state,
                        peer,
                        "tcp",
                        RULE_PROXY_PROTOCOL,
                        "peer is not in proxy_protocol.trusted_proxy_networks",
                    );
                    drop(stream);
                    continue;
                }
                if let Some((rule, detail)) = handshake_precheck(&state, peer, state.tls.is_some()) {
                    record_transport_reject(&state, peer, "tcp", rule, &detail);
                    drop(stream);
                    continue;
                }
                let Some(guard) = state.connections.try_acquire(peer.ip()) else {
                    record_transport_reject(
                        &state,
                        peer,
                        "tcp",
                        RULE_CONNECTION_BUDGET,
                        "connection budget is exhausted",
                    );
                    drop(stream);
                    continue;
                };
                let _ = stream.set_nodelay(true);
                let task_state = state.clone();
                let task_shutdown = shutdown.clone();
                tasks.spawn(async move {
                    handle_tcp_connection(stream, peer, guard, task_state, task_shutdown).await;
                });
            }
        }
    }

    let _ = timeout(Duration::from_secs(10), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    Ok(())
}

fn next_accept_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(ACCEPT_RETRY_MAX)
}

fn is_transient_accept_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::OutOfMemory
    ) {
        return true;
    }
    is_accept_resource_exhaustion(error)
}

#[cfg(unix)]
fn is_accept_resource_exhaustion(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

#[cfg(windows)]
fn is_accept_resource_exhaustion(error: &io::Error) -> bool {
    use windows_sys::Win32::Networking::WinSock::{
        WSAECONNABORTED, WSAECONNRESET, WSAEINTR, WSAEMFILE, WSAENOBUFS, WSAEWOULDBLOCK,
    };

    matches!(
        error.raw_os_error(),
        Some(WSAEINTR | WSAEWOULDBLOCK | WSAECONNABORTED | WSAECONNRESET | WSAEMFILE | WSAENOBUFS)
    )
}

#[cfg(not(any(unix, windows)))]
fn is_accept_resource_exhaustion(_error: &io::Error) -> bool {
    false
}

async fn handle_proxied_tcp_connection(
    mut stream: TcpStream,
    raw_peer: SocketAddr,
    pending: PendingConnectionGuard,
    state: Arc<AppState>,
    shutdown: watch::Receiver<bool>,
) {
    let header_timeout =
        Duration::from_millis(state.config.listen.proxy_protocol.header_timeout_ms);
    let resolved = match proxy_protocol::resolve_peer(
        &mut stream,
        raw_peer,
        &state.config.listen.proxy_protocol,
        header_timeout,
    )
    .await
    {
        Ok(resolved) => resolved,
        Err(error) => {
            record_transport_reject(
                &state,
                raw_peer,
                "tcp",
                RULE_PROXY_PROTOCOL,
                &error.to_string(),
            );
            return;
        }
    };

    let peer = resolved.peer;
    if let Some((rule, detail)) = handshake_precheck(&state, peer, state.tls.is_some()) {
        record_transport_reject(&state, peer, "tcp", rule, &detail);
        return;
    }
    let Some(guard) = pending.try_classify(peer.ip()) else {
        record_transport_reject(
            &state,
            peer,
            "tcp",
            RULE_CONNECTION_BUDGET,
            "connection budget is exhausted for the resolved client address",
        );
        return;
    };
    tracing::debug!(
        raw_peer = %raw_peer,
        peer = %peer,
        used_proxy_header = resolved.used_proxy_header,
        "resolved TCP client source"
    );
    handle_tcp_connection(stream, peer, guard, state, shutdown).await;
}

async fn handle_tcp_connection(
    stream: TcpStream,
    peer: SocketAddr,
    _guard: ConnectionGuard,
    state: Arc<AppState>,
    shutdown: watch::Receiver<bool>,
) {
    let result = if let Some(bundle) = state.tls.as_ref() {
        let handshake_timeout = Duration::from_millis(state.config.limits.tls_handshake_timeout_ms);
        match timeout(handshake_timeout, bundle.acceptor.accept(stream)).await {
            Ok(Ok(stream)) => serve_tls_connection(stream, peer, state, shutdown).await,
            Ok(Err(error)) => {
                record_transport_reject(
                    &state,
                    peer,
                    "tls",
                    RULE_TLS_PROTOCOL,
                    &format!("TLS handshake failed: {error}"),
                );
                Ok(())
            }
            Err(_) => {
                record_transport_reject(
                    &state,
                    peer,
                    "tls",
                    "HW-NATIVE-TIMEOUT-001",
                    "TLS handshake timed out",
                );
                Ok(())
            }
        }
    } else {
        run_h1(
            stream,
            peer,
            TlsConnectionInfo::default(),
            state.clone(),
            shutdown,
        )
        .await
    };
    if let Err(error) = result {
        tracing::debug!(peer = %peer, error = %error, "TCP connection closed with an error");
    }
}

async fn serve_tls_connection(
    stream: TlsStream<TcpStream>,
    peer: SocketAddr,
    state: Arc<AppState>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let info = TlsConnectionInfo::from_connection(stream.get_ref().1);
    if info.version.is_none() {
        record_transport_reject(
            &state,
            peer,
            "tls",
            RULE_TLS_PROTOCOL,
            "TLS session has no negotiated protocol version",
        );
        return Ok(());
    }
    match info.alpn.as_deref() {
        Some("h2") => h2_server::serve_connection(stream, peer, info, state, shutdown).await,
        Some("http/1.1") => run_h1(stream, peer, info, state, shutdown).await,
        Some(alpn) => {
            record_transport_reject(
                &state,
                peer,
                "tls",
                RULE_TLS_PROTOCOL,
                &format!("unsupported ALPN protocol: {alpn}"),
            );
            Ok(())
        }
        None => {
            record_transport_reject(
                &state,
                peer,
                "tls",
                RULE_TLS_PROTOCOL,
                "TLS client did not negotiate an ALPN protocol",
            );
            Ok(())
        }
    }
}

async fn run_h1<S>(
    stream: S,
    peer: SocketAddr,
    tls_info: TlsConnectionInfo,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if *shutdown.borrow() {
        return Ok(());
    }
    tokio::select! {
        result = h1_server::serve_connection(stream, peer, tls_info, state) => result,
        _ = wait_for_shutdown(&mut shutdown) => Ok(()),
    }
}

async fn quic_accept_loop(
    endpoint: Option<quinn::Endpoint>,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let Some(endpoint) = endpoint else {
        wait_for_shutdown(&mut shutdown).await;
        return Ok(());
    };
    let quic = state
        .config
        .quic
        .as_ref()
        .filter(|quic| quic.enabled)
        .ok_or_else(|| {
            CoreError::Config("QUIC endpoint exists without QUIC configuration".to_string())
        })?;
    let handshakes = Arc::new(Semaphore::new(quic.max_inflight_handshakes));
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = joined {
                    tracing::warn!(error = %error, "QUIC connection task failed");
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    if *shutdown.borrow() {
                        break;
                    }
                    return Err(CoreError::Protocol("QUIC endpoint stopped unexpectedly".to_string()));
                };
                let peer = incoming.remote_address();
                if !quic.allows(peer.ip()) {
                    record_transport_reject(
                        &state,
                        peer,
                        "quic",
                        RULE_QUIC_ACL,
                        "peer is not in quic.allowed_client_networks",
                    );
                    incoming.ignore();
                    continue;
                }
                if let Some((rule, detail)) = handshake_precheck(&state, peer, true) {
                    record_transport_reject(&state, peer, "quic", rule, &detail);
                    incoming.ignore();
                    continue;
                }
                if quic.require_retry && !incoming.remote_address_validated() {
                    if incoming.may_retry() {
                        if let Err(error) = incoming.retry() {
                            tracing::debug!(peer = %peer, error = %error, "QUIC Retry was not accepted");
                        }
                    } else {
                        incoming.refuse();
                    }
                    continue;
                }
                let Some(guard) = state.connections.try_acquire(peer.ip()) else {
                    record_transport_reject(
                        &state,
                        peer,
                        "quic",
                        RULE_CONNECTION_BUDGET,
                        "connection budget is exhausted",
                    );
                    incoming.ignore();
                    continue;
                };
                let permit = match handshakes.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        incoming.refuse();
                        continue;
                    }
                };
                let task_state = state.clone();
                let task_shutdown = shutdown.clone();
                tasks.spawn(async move {
                    handle_quic_incoming(incoming, guard, permit, task_state, task_shutdown).await;
                });
            }
        }
    }

    endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
    let _ = timeout(Duration::from_secs(10), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    let _ = timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    Ok(())
}

async fn handle_quic_incoming(
    incoming: quinn::Incoming,
    _guard: ConnectionGuard,
    handshake_permit: OwnedSemaphorePermit,
    state: Arc<AppState>,
    shutdown: watch::Receiver<bool>,
) {
    let peer = incoming.remote_address();
    let connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(error) => {
            record_transport_reject(
                &state,
                peer,
                "quic",
                RULE_QUIC_PROTOCOL,
                &format!("QUIC accept failed: {error}"),
            );
            return;
        }
    };
    let handshake_timeout = Duration::from_millis(
        state
            .config
            .quic
            .as_ref()
            .map(|quic| quic.handshake_timeout_ms)
            .unwrap_or(state.config.limits.tls_handshake_timeout_ms),
    );
    let connection = match timeout(handshake_timeout, connecting).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            record_transport_reject(
                &state,
                peer,
                "quic",
                RULE_QUIC_PROTOCOL,
                &format!("QUIC handshake failed: {error}"),
            );
            return;
        }
        Err(_) => {
            record_transport_reject(
                &state,
                peer,
                "quic",
                "HW-NATIVE-TIMEOUT-001",
                "QUIC handshake timed out",
            );
            return;
        }
    };
    drop(handshake_permit);
    let Some(handshake) = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
    else {
        record_transport_reject(
            &state,
            peer,
            "quic",
            RULE_QUIC_PROTOCOL,
            "QUIC handshake metadata is unavailable",
        );
        connection.close(quinn::VarInt::from_u32(0x0100), b"TLS metadata unavailable");
        return;
    };
    if handshake.protocol.as_deref() != Some(b"h3") {
        record_transport_reject(
            &state,
            peer,
            "quic",
            RULE_QUIC_PROTOCOL,
            "QUIC client did not negotiate h3 ALPN",
        );
        connection.close(quinn::VarInt::from_u32(0x0100), b"h3 ALPN is required");
        return;
    }
    let tls_info =
        TlsConnectionInfo::from_quic(handshake.server_name.clone(), handshake.protocol.clone());
    if let Err(error) =
        h3_server::serve_connection(connection, peer, tls_info, state.clone(), shutdown).await
    {
        tracing::debug!(peer = %peer, error = %error, "QUIC connection closed with an error");
    }
}

fn handshake_precheck(
    state: &AppState,
    peer: SocketAddr,
    secure_handshake: bool,
) -> Option<(&'static str, String)> {
    if secure_handshake && !state.handshake_rate.check(peer.ip()).permit {
        return Some((
            RULE_HANDSHAKE_RATE,
            "TLS/QUIC handshake rate exceeded".to_string(),
        ));
    }
    None
}

fn record_transport_reject(
    state: &AppState,
    peer: SocketAddr,
    protocol: &str,
    rule: &str,
    detail: &str,
) {
    let mut event = AuditEvent::new(
        next_request_id(),
        peer.to_string(),
        protocol,
        "-",
        "/",
        "unmatched",
        "deny",
        0,
    );
    event.rule_ids = vec![rule.to_string()];
    event.detail = Some(detail.chars().take(200).collect());
    let _ = state.audit.record(event);
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    loop {
        if shutdown.changed().await.is_err() || *shutdown.borrow() {
            return;
        }
    }
}

async fn finish_task(mut task: JoinHandle<Result<()>>, label: &str) -> Result<()> {
    match timeout(Duration::from_secs(12), &mut task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(CoreError::Protocol(format!("{label} task failed: {error}"))),
        Err(_) => {
            task.abort();
            Err(CoreError::Protocol(format!("{label} did not stop in time")))
        }
    }
}

fn unexpected_task_result(
    result: std::result::Result<Result<()>, JoinError>,
    label: &str,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Err(CoreError::Protocol(format!(
            "{label} stopped without a shutdown request"
        ))),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(CoreError::Protocol(format!("{label} task failed: {error}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_transient_accept_errors() {
        for kind in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::OutOfMemory,
        ] {
            assert!(is_transient_accept_error(&io::Error::from(kind)));
        }
        assert!(!is_transient_accept_error(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }

    #[cfg(unix)]
    #[test]
    fn classifies_unix_file_descriptor_exhaustion() {
        let error = io::Error::from_raw_os_error(libc::EMFILE);
        assert!(is_transient_accept_error(&error));
    }

    #[cfg(windows)]
    #[test]
    fn classifies_windows_socket_exhaustion() {
        use windows_sys::Win32::Networking::WinSock::WSAEMFILE;

        let error = io::Error::from_raw_os_error(WSAEMFILE);
        assert!(is_transient_accept_error(&error));
    }

    #[test]
    fn accept_backoff_is_bounded() {
        let mut delay = ACCEPT_RETRY_INITIAL;
        for _ in 0..16 {
            delay = next_accept_backoff(delay);
        }
        assert_eq!(delay, ACCEPT_RETRY_MAX);
    }
}
