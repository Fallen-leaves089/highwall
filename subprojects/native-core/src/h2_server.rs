use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant as StdInstant},
};

use bytes::Bytes;
use h2::{server::SendResponse, RecvStream};
use http::{Response, StatusCode};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{sleep_until, timeout, Instant},
};

use crate::{
    audit::{next_request_id, normalized_path, AuditEvent},
    error::{CoreError, Result},
    gateway::{process_request, GatewayRequest, GatewayResponse},
    http::{
        fields_from_http_headers, fields_to_http_headers, request_head_from_http_parts,
        response_fields_for_h2_h3, validate_trailer_fields, HeaderField, HttpVersion, RequestHead,
    },
    limits::H2ConnectionBudget,
    policy::select_route,
    state::AppState,
    tls::TlsConnectionInfo,
};

const RULE_H2_PROTOCOL: &str = "HW-NATIVE-H2-001";
const RULE_H2_BODY: &str = "HW-NATIVE-H2-002";
const RULE_H2_CLIENT_RESET: &str = "HW-NATIVE-H2-003";
const RULE_H2_EXHAUSTED: &str = "HW-NATIVE-H2-004";
const RULE_H2_PING_BUDGET: &str = "HW-NATIVE-H2-005";
const H2_PREFACE_BYTES: usize = 24;
const H2_SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
const H2_TASK_DRAIN_GRACE: Duration = Duration::from_secs(2);

struct H2PingGuard<S> {
    inner: S,
    parser: H2PingParser,
    violated: Arc<AtomicBool>,
}

impl<S> H2PingGuard<S> {
    fn new(
        inner: S,
        rate_per_second: f64,
        burst: f64,
        max_frames: usize,
        violated: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner,
            parser: H2PingParser::new(rate_per_second, burst, max_frames),
            violated,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for H2PingGuard<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            let after = buf.filled().len();
            if after > before {
                if let Err(error) = this.parser.consume(&buf.filled()[before..after]) {
                    this.violated.store(true, Ordering::Relaxed);
                    return Poll::Ready(Err(error));
                }
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for H2PingGuard<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}

struct H2PingParser {
    preface_remaining: usize,
    header: [u8; 9],
    header_len: usize,
    frame_remaining: u32,
    rate_per_second: f64,
    burst: f64,
    tokens: f64,
    last: StdInstant,
    max_frames: usize,
    frames_seen: usize,
}

impl H2PingParser {
    fn new(rate_per_second: f64, burst: f64, max_frames: usize) -> Self {
        Self {
            preface_remaining: H2_PREFACE_BYTES,
            header: [0; 9],
            header_len: 0,
            frame_remaining: 0,
            rate_per_second,
            burst,
            tokens: burst,
            last: StdInstant::now(),
            max_frames,
            frames_seen: 0,
        }
    }

    fn consume(&mut self, bytes: &[u8]) -> io::Result<()> {
        for &byte in bytes {
            if self.preface_remaining > 0 {
                self.preface_remaining -= 1;
                continue;
            }
            if self.frame_remaining > 0 {
                self.frame_remaining -= 1;
                continue;
            }
            self.header[self.header_len] = byte;
            self.header_len += 1;
            if self.header_len == self.header.len() {
                let length = (u32::from(self.header[0]) << 16)
                    | (u32::from(self.header[1]) << 8)
                    | u32::from(self.header[2]);
                let frame_type = self.header[3];
                self.header_len = 0;
                self.frame_remaining = length;
                if frame_type == 0x6 {
                    self.observe_ping()?;
                }
            }
        }
        Ok(())
    }

    fn observe_ping(&mut self) -> io::Result<()> {
        let now = StdInstant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate_per_second).min(self.burst);
        self.last = now;
        self.frames_seen = self.frames_seen.saturating_add(1);
        if self.frames_seen > self.max_frames {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HTTP/2 PING frame budget exceeded",
            ));
        }
        if self.tokens < 1.0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HTTP/2 PING rate exceeded",
            ));
        }
        self.tokens -= 1.0;
        Ok(())
    }
}

#[derive(Debug)]
struct StreamOutcome {
    reset: bool,
}

#[derive(Debug)]
struct H2Reject {
    status: u16,
    rule: &'static str,
    detail: String,
    request_id: u64,
    method: String,
    path: String,
    client_reset: bool,
}

pub async fn serve_connection<S>(
    stream: S,
    peer: SocketAddr,
    tls_info: TlsConnectionInfo,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = &state.config.limits;
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(limits.max_h2_stream_window_bytes)
        .initial_connection_window_size(limits.max_h2_connection_window_bytes)
        .max_concurrent_streams(limits.max_h2_streams)
        .max_header_list_size(limits.max_h2_header_list_bytes as u32)
        .max_frame_size(limits.max_h2_frame_size)
        .max_send_buffer_size(limits.max_h2_send_buffer_bytes)
        .max_concurrent_reset_streams(limits.max_h2_reset_errors)
        .max_pending_accept_reset_streams(limits.max_h2_reset_errors)
        .max_local_error_reset_streams(Some(limits.max_h2_reset_errors));

    let ping_violation = Arc::new(AtomicBool::new(false));
    let guarded = H2PingGuard::new(
        stream,
        limits.max_h2_pings_per_second,
        limits.max_h2_ping_burst,
        limits.max_h2_ping_frames_per_connection,
        ping_violation.clone(),
    );
    let handshake_timeout = Duration::from_millis(limits.header_timeout_ms.max(1));
    let mut connection = match timeout(handshake_timeout, builder.handshake(guarded)).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            if ping_violation.load(Ordering::Relaxed) {
                record_ping_violation(&state, peer, &tls_info);
            }
            return Err(CoreError::Protocol(format!(
                "HTTP/2 handshake failed: {error}"
            )));
        }
        Err(_) => {
            return Err(CoreError::Protocol(
                "HTTP/2 handshake timed out".to_string(),
            ))
        }
    };
    let max_tasks = limits.max_h2_streams.max(1) as usize;
    let permits = Arc::new(Semaphore::new(max_tasks));
    let reset_count = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::<StreamOutcome>::new();
    let mut budget = H2ConnectionBudget::new(
        limits.max_h2_requests_per_connection,
        limits.max_h2_reset_errors,
    );
    let mut shutting_down = *shutdown.borrow();
    let mut shutdown_deadline = shutting_down.then(|| Instant::now() + H2_SHUTDOWN_GRACE);
    let idle_timeout = Duration::from_millis(limits.h2_idle_timeout_ms.max(1));
    let mut last_activity = Instant::now();

    loop {
        let shutdown_wait_deadline = shutdown_deadline;
        let idle_deadline = last_activity + idle_timeout;
        tokio::select! {
            joined = tasks.join_next(), if !tasks.is_empty() => {
                last_activity = Instant::now();
                if handle_join(joined, &state, peer, &tls_info, &reset_count, limits.max_h2_reset_errors) {
                    connection.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                    return Ok(());
                }
            }
            accepted = connection.accept() => {
                last_activity = Instant::now();
                match accepted {
                    Some(Ok((request, mut respond))) => {
                        if shutting_down || !budget.accept_request() {
                            respond.send_reset(h2::Reason::REFUSED_STREAM);
                            if !shutting_down {
                                connection.graceful_shutdown();
                                shutting_down = true;
                                shutdown_deadline = Some(Instant::now() + H2_SHUTDOWN_GRACE);
                            }
                            continue;
                        }
                        let permit = match permits.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                respond.send_reset(h2::Reason::REFUSED_STREAM);
                                state.bans.note_violation(peer.ip(), RULE_H2_EXHAUSTED);
                                continue;
                            }
                        };
                        let task_state = state.clone();
                        let task_tls = tls_info.clone();
                        let task_resets = reset_count.clone();
                        tasks.spawn(async move {
            handle_stream(request, respond, peer, task_tls, task_state, permit, task_resets).await
                        });
                    }
                    Some(Err(error)) => {
                        if ping_violation.load(Ordering::Relaxed) {
                            record_ping_violation(&state, peer, &tls_info);
                        }
                        tracing::debug!(error = %error, "HTTP/2 connection closed with an error");
                        break;
                    }
                    None => break,
                }
            }
            changed = shutdown.changed() => {
                if (changed.is_err() || *shutdown.borrow()) && !shutting_down {
                    connection.graceful_shutdown();
                    shutting_down = true;
                    shutdown_deadline = Some(Instant::now() + H2_SHUTDOWN_GRACE);
                }
            }
            _ = async move {
                match shutdown_wait_deadline {
                    Some(deadline) => sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                tracing::warn!("HTTP/2 graceful shutdown deadline reached; closing the connection");
                connection.abrupt_shutdown(h2::Reason::NO_ERROR);
                break;
            }
            _ = sleep_until(idle_deadline) => {
                if tasks.is_empty() {
                    tracing::debug!("HTTP/2 connection idle timeout reached; closing the connection");
                    connection.abrupt_shutdown(h2::Reason::NO_ERROR);
                    break;
                }
                last_activity = Instant::now();
            }
        }
    }

    let _ = timeout(H2_TASK_DRAIN_GRACE, async {
        while let Some(joined) = tasks.join_next().await {
            let _ = handle_join(
                Some(joined),
                &state,
                peer,
                &tls_info,
                &reset_count,
                limits.max_h2_reset_errors,
            );
        }
    })
    .await;
    tasks.abort_all();
    Ok(())
}

fn record_ping_violation(state: &AppState, peer: SocketAddr, tls_info: &TlsConnectionInfo) {
    let mut event = AuditEvent::new(
        next_request_id(),
        peer.to_string(),
        "h2",
        "-",
        "/",
        "unmatched",
        "deny",
        0,
    );
    event.rule_ids = vec![RULE_H2_PING_BUDGET.to_string()];
    event.detail = Some("HTTP/2 PING rate or connection budget exceeded".to_string());
    event.tls_server_name = tls_info.server_name.clone();
    event.tls_version = tls_info.version.clone();
    event.alpn = tls_info.alpn.clone();
    let _ = state.audit.record(event);
}

fn handle_join(
    joined: Option<std::result::Result<StreamOutcome, tokio::task::JoinError>>,
    state: &AppState,
    peer: SocketAddr,
    tls_info: &TlsConnectionInfo,
    reset_count: &AtomicUsize,
    max_resets: usize,
) -> bool {
    match joined {
        Some(Ok(outcome)) if outcome.reset => {
            reset_count.fetch_add(1, Ordering::Relaxed) + 1 > max_resets
        }
        Some(Ok(_)) => false,
        Some(Err(error)) => {
            tracing::warn!(error = %error, "HTTP/2 request task failed");
            let mut event = AuditEvent::new(
                next_request_id(),
                peer.to_string(),
                "h2",
                "-",
                "/",
                "unmatched",
                "deny",
                500,
            );
            event.rule_ids = vec![RULE_H2_PROTOCOL.to_string()];
            event.detail = Some("HTTP/2 request task terminated unexpectedly".to_string());
            event.tls_server_name = tls_info.server_name.clone();
            event.tls_version = tls_info.version.clone();
            event.alpn = tls_info.alpn.clone();
            let _ = state.audit.record(event);
            false
        }
        None => false,
    }
}

async fn handle_stream(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    peer: SocketAddr,
    tls_info: TlsConnectionInfo,
    state: Arc<AppState>,
    _permit: OwnedSemaphorePermit,
    _reset_count: Arc<AtomicUsize>,
) -> StreamOutcome {
    let total = Duration::from_millis(state.config.limits.request_total_timeout_ms);
    let started = Instant::now();
    let mut request_id = next_request_id();
    let mut method = request.method().as_str().to_string();
    let mut path = "/".to_string();

    let outcome = timeout(
        total,
        process_h2_request(
            request,
            &mut respond,
            peer,
            &tls_info,
            state.clone(),
            &mut request_id,
            &mut method,
            &mut path,
        ),
    )
    .await;

    match outcome {
        Ok(Ok(())) => StreamOutcome { reset: false },
        Ok(Err(reject)) => {
            let sent = send_synthetic(
                &mut respond,
                &reject.method,
                reject.status,
                reject.rule,
                &reject.detail,
            )
            .await
            .is_ok();
            record_reject(&state, peer, &tls_info, &reject);
            StreamOutcome {
                reset: reject.client_reset || !sent,
            }
        }
        Err(_) => {
            let reject = H2Reject {
                status: 504,
                rule: "HW-NATIVE-TIMEOUT-001",
                detail: "HTTP/2 request timed out".to_string(),
                request_id,
                method: method.clone(),
                path: path.clone(),
                client_reset: false,
            };
            let _ = send_synthetic(&mut respond, &method, 504, reject.rule, &reject.detail).await;
            record_reject(&state, peer, &tls_info, &reject);
            StreamOutcome { reset: false }
        }
    }
    .tap(|_| {
        tracing::trace!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "HTTP/2 request completed"
        )
    })
}

#[allow(clippy::too_many_arguments)]
async fn process_h2_request(
    request: http::Request<RecvStream>,
    respond: &mut SendResponse<Bytes>,
    peer: SocketAddr,
    tls_info: &TlsConnectionInfo,
    state: Arc<AppState>,
    request_id: &mut u64,
    method_out: &mut String,
    path_out: &mut String,
) -> std::result::Result<(), H2Reject> {
    if request.extensions().get::<h2::ext::Protocol>().is_some() {
        return Err(reject(
            *request_id,
            method_out,
            path_out,
            400,
            RULE_H2_PROTOCOL,
            "extended CONNECT is not accepted",
            false,
        ));
    }
    let (parts, mut recv) = request.into_parts();
    *method_out = parts.method.as_str().to_string();
    let head = match request_head_from_http_parts(
        &parts.method,
        &parts.uri,
        &parts.headers,
        HttpVersion::Http2,
        true,
        &state.config.limits,
    ) {
        Ok(head) => head,
        Err(error) => {
            return Err(reject(
                *request_id,
                method_out,
                path_out,
                400,
                RULE_H2_PROTOCOL,
                &error.to_string(),
                false,
            ))
        }
    };
    *path_out = normalized_path(&head.target);
    let route = match select_route(&state.config, &head) {
        Some(route) => route,
        None => {
            return Err(reject(
                *request_id,
                method_out,
                path_out,
                403,
                "HW-NATIVE-ROUTE-001",
                "no explicit route allows this request",
                false,
            ))
        }
    };
    let body_limit = route
        .max_body_bytes
        .unwrap_or(state.config.limits.max_body_bytes);
    if head
        .content_length
        .is_some_and(|length| length > body_limit as u64)
    {
        return Err(reject(
            *request_id,
            method_out,
            path_out,
            413,
            RULE_H2_BODY,
            "declared request body exceeds the route limit",
            false,
        ));
    }
    let (body, trailers) = match read_body(&mut recv, body_limit, &state.config.limits).await {
        Ok(value) => value,
        Err((error, client_reset)) => {
            let status = match error {
                CoreError::Limit(_) => 413,
                _ => 400,
            };
            return Err(reject(
                *request_id,
                method_out,
                path_out,
                status,
                if client_reset {
                    RULE_H2_CLIENT_RESET
                } else {
                    RULE_H2_BODY
                },
                &error.to_string(),
                client_reset,
            ));
        }
    };
    if let Some(length) = head.content_length {
        if length != body.len() as u64 {
            return Err(reject(
                *request_id,
                method_out,
                path_out,
                400,
                RULE_H2_PROTOCOL,
                "Content-Length does not match the received body",
                false,
            ));
        }
    }

    let gateway_request = GatewayRequest {
        request_id: *request_id,
        head: head.clone(),
        body,
        trailers,
        peer,
        tls: tls_info.clone(),
        secure_transport: true,
    };
    let response = process_request(gateway_request, state).await;
    if let Err(error) = send_gateway_response(respond, &head, &response).await {
        return Err(reject(
            *request_id,
            method_out,
            path_out,
            400,
            RULE_H2_CLIENT_RESET,
            &error.to_string(),
            true,
        ));
    }
    Ok(())
}

fn reject(
    request_id: u64,
    method: &str,
    path: &str,
    status: u16,
    rule: &'static str,
    detail: &str,
    client_reset: bool,
) -> H2Reject {
    H2Reject {
        status,
        rule,
        detail: detail.chars().take(200).collect(),
        request_id,
        method: method.to_string(),
        path: path.to_string(),
        client_reset,
    }
}

async fn read_body(
    recv: &mut RecvStream,
    max_bytes: usize,
    limits: &crate::config::LimitsConfig,
) -> std::result::Result<(Vec<u8>, Vec<HeaderField>), (CoreError, bool)> {
    let idle = Duration::from_millis(limits.body_idle_timeout_ms);
    let mut body = Vec::new();
    loop {
        let chunk = match timeout(idle, recv.data()).await {
            Ok(Some(Ok(chunk))) => chunk,
            Ok(Some(Err(error))) => {
                return Err((
                    CoreError::Protocol(format!("HTTP/2 request stream failed: {error}")),
                    true,
                ))
            }
            Ok(None) => break,
            Err(_) => {
                return Err((
                    CoreError::Limit("HTTP/2 request body timed out".to_string()),
                    false,
                ))
            }
        };
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err((
                CoreError::Limit("HTTP/2 request body exceeds the route limit".to_string()),
                false,
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let trailers = match timeout(idle, recv.trailers()).await {
        Ok(Ok(Some(trailers))) => {
            fields_from_http_headers(&trailers, limits).map_err(|error| (error, false))?
        }
        Ok(Ok(None)) => Vec::new(),
        Ok(Err(error)) => {
            return Err((
                CoreError::Protocol(format!("HTTP/2 trailers failed: {error}")),
                true,
            ))
        }
        Err(_) => {
            return Err((
                CoreError::Limit("HTTP/2 request trailers timed out".to_string()),
                false,
            ))
        }
    };
    validate_trailer_fields(&trailers).map_err(|error| (error, false))?;
    Ok((body, trailers))
}

async fn send_gateway_response(
    respond: &mut SendResponse<Bytes>,
    request: &RequestHead,
    response: &GatewayResponse,
) -> Result<()> {
    if (100..200).contains(&response.head.status) {
        return Err(CoreError::Protocol(
            "informational upstream responses are not accepted on HTTP/2".to_string(),
        ));
    }
    let status = StatusCode::from_u16(response.head.status)
        .map_err(|_| CoreError::Protocol("invalid HTTP/2 response status".to_string()))?;
    let no_body = request.method == "HEAD"
        || response.head.status == 204
        || response.head.status == 304
        || (100..200).contains(&response.head.status);
    let content_length = if request.method == "HEAD" {
        response
            .head
            .content_length
            .unwrap_or(response.body.len() as u64)
    } else {
        response.body.len() as u64
    };
    let fields =
        response_fields_for_h2_h3(&response.head.headers, content_length, response.head.status)?;
    let headers = fields_to_http_headers(&fields)?;
    let mut builder = Response::builder().status(status);
    *builder
        .headers_mut()
        .ok_or_else(|| CoreError::Protocol("cannot build HTTP/2 response".to_string()))? = headers;
    let response_head = builder
        .body(())
        .map_err(|error| CoreError::Protocol(format!("invalid HTTP/2 response: {error}")))?;
    let trailers = if response.trailers.is_empty() || no_body {
        None
    } else {
        validate_trailer_fields(&response.trailers)?;
        Some(fields_to_http_headers(&response.trailers)?)
    };
    let send_body = !no_body && !response.body.is_empty();
    let mut send_stream = respond
        .send_response(response_head, !send_body && trailers.is_none())
        .map_err(|error| CoreError::Protocol(format!("HTTP/2 response headers failed: {error}")))?;
    if send_body {
        send_stream
            .send_data(Bytes::copy_from_slice(&response.body), trailers.is_none())
            .map_err(|error| {
                CoreError::Protocol(format!("HTTP/2 response body failed: {error}"))
            })?;
    }
    if let Some(trailers) = trailers {
        send_stream
            .send_trailers(trailers)
            .map_err(|error| CoreError::Protocol(format!("HTTP/2 trailers failed: {error}")))?;
    }
    Ok(())
}

async fn send_synthetic(
    respond: &mut SendResponse<Bytes>,
    method: &str,
    status: u16,
    rule: &str,
    detail: &str,
) -> Result<()> {
    let response = GatewayResponse::synthetic(HttpVersion::Http2, status, rule, detail);
    let mut head = RequestHead {
        method: if method == "HEAD" { "HEAD" } else { "GET" }.to_string(),
        target: "/".to_string(),
        path: "/".to_string(),
        query: None,
        version: HttpVersion::Http2,
        headers: Vec::new(),
        host: String::new(),
        content_length: None,
        chunked: false,
        connection_tokens: Default::default(),
        upgrade: None,
    };
    head.version = HttpVersion::Http2;
    send_gateway_response(respond, &head, &response).await
}

fn record_reject(
    state: &AppState,
    peer: SocketAddr,
    tls_info: &TlsConnectionInfo,
    reject: &H2Reject,
) {
    let mut event = AuditEvent::new(
        reject.request_id,
        peer.to_string(),
        "h2",
        &reject.method,
        &reject.path,
        "unmatched",
        "deny",
        reject.status,
    );
    event.rule_ids = vec![reject.rule.to_string()];
    event.detail = Some(reject.detail.clone());
    event.tls_server_name = tls_info.server_name.clone();
    event.tls_version = tls_info.version.clone();
    event.alpn = tls_info.alpn.clone();
    let _ = state.audit.record(event);
}

trait Tap: Sized {
    fn tap(self, f: impl FnOnce(&Self)) -> Self {
        f(&self);
        self
    }
}

impl<T> Tap for T {}
