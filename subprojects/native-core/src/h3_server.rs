use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use http::{Response, StatusCode};
use tokio::{
    sync::{watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{timeout, Instant},
};

use crate::{
    audit::{next_request_id, normalized_path, AuditEvent},
    config::QuicConfig,
    error::{CoreError, Result},
    gateway::{process_request, GatewayRequest, GatewayResponse},
    http::{
        fields_from_http_headers, fields_to_http_headers, request_head_from_http_parts,
        response_fields_for_h2_h3, validate_trailer_fields, HeaderField, HttpVersion, RequestHead,
    },
    policy::select_route,
    state::AppState,
    tls::TlsConnectionInfo,
};

const RULE_H3_PROTOCOL: &str = "HW-NATIVE-H3-001";
const RULE_H3_BODY: &str = "HW-NATIVE-H3-002";
const RULE_H3_CLIENT_RESET: &str = "HW-NATIVE-H3-003";
const RULE_H3_EXHAUSTED: &str = "HW-NATIVE-H3-004";
const RULE_H3_AUTHORITY_MISSING: &str = "HW-NATIVE-H3-AUTHORITY-001";
const RULE_H3_AUTHORITY_MISMATCH: &str = "HW-NATIVE-H3-AUTHORITY-002";
const H3_EXCESSIVE_LOAD: u32 = 0x0107;
const H3_SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
const H3_TASK_DRAIN_GRACE: Duration = Duration::from_secs(2);

type H3Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[derive(Debug)]
struct StreamOutcome {
    reset: bool,
}

#[derive(Debug)]
struct H3Reject {
    status: u16,
    rule: &'static str,
    detail: String,
    request_id: u64,
    method: String,
    path: String,
    client_reset: bool,
}

#[derive(Debug, Copy, Clone)]
struct H3AuthorityReject {
    rule: &'static str,
    kind: &'static str,
    response_sent: bool,
}

pub fn build_quic_server_config(
    config: &QuicConfig,
    crypto: &rustls::ServerConfig,
) -> Result<quinn::ServerConfig> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto.clone())
        .map_err(|error| CoreError::Config(format!("QUIC TLS configuration failed: {error}")))?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(config.max_concurrent_bidi_streams))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(config.max_concurrent_uni_streams))
        .stream_receive_window(
            quinn::VarInt::from_u64(config.stream_receive_window_bytes)
                .map_err(|_| CoreError::Config("QUIC stream window is out of range".to_string()))?,
        )
        .receive_window(
            quinn::VarInt::from_u64(config.connection_receive_window_bytes).map_err(|_| {
                CoreError::Config("QUIC connection window is out of range".to_string())
            })?,
        )
        .initial_mtu(config.max_udp_payload_size)
        .min_mtu(1200);
    let idle_timeout: quinn::IdleTimeout = Duration::from_millis(config.max_idle_timeout_ms)
        .try_into()
        .map_err(|_| CoreError::Config("QUIC idle timeout is out of range".to_string()))?;
    transport.max_idle_timeout(Some(idle_timeout));

    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server
        .transport_config(Arc::new(transport))
        .migration(config.allow_migration)
        .max_incoming(config.max_inflight_handshakes)
        .incoming_buffer_size(64 * 1024)
        .incoming_buffer_size_total(
            (64_u64 * 1024)
                .saturating_mul(config.max_inflight_handshakes as u64)
                .min(16 * 1024 * 1024),
        )
        .retry_token_lifetime(
            Duration::from_millis(config.handshake_timeout_ms.max(1_000))
                .min(Duration::from_secs(30)),
        );
    Ok(server)
}

pub async fn serve_connection(
    connection: quinn::Connection,
    peer: SocketAddr,
    tls_info: TlsConnectionInfo,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let limits = &state.config.limits;
    let mut builder = h3::server::builder();
    builder
        .max_field_section_size(limits.max_h3_field_section_bytes)
        .enable_extended_connect(false)
        .enable_datagram(false)
        .enable_webtransport(false);
    let mut h3_connection: H3Connection = builder
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| CoreError::Protocol(format!("HTTP/3 handshake failed: {error}")))?;
    tracing::trace!(peer = %peer, "HTTP/3 connection driver ready");

    let permits = Arc::new(Semaphore::new(limits.max_h3_streams.max(1) as usize));
    let reset_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = JoinSet::<StreamOutcome>::new();
    let mut requests = 0_usize;
    let mut shutting_down = *shutdown.borrow();
    let mut shutdown_deadline = shutting_down.then(|| Instant::now() + H3_SHUTDOWN_GRACE);
    if shutting_down {
        let _ = timeout(Duration::from_millis(500), h3_connection.shutdown(0)).await;
    }

    loop {
        let shutdown_wait_deadline = shutdown_deadline;
        tokio::select! {
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if handle_join(
                    joined,
                    &state,
                    peer,
                    &tls_info,
                    &reset_count,
                    limits.max_h3_reset_errors,
                ) {
                    connection.close(
                        quinn::VarInt::from_u32(H3_EXCESSIVE_LOAD),
                        b"HTTP/3 reset budget exceeded",
                    );
                    return Ok(());
                }
            }
            accepted = h3_connection.accept() => {
                match accepted {
                    Ok(Some(resolver)) => {
                        tracing::trace!(peer = %peer, requests, "HTTP/3 request resolver accepted");
                        if shutting_down || requests >= limits.max_h3_requests_per_connection {
                            connection.close(
                                quinn::VarInt::from_u32(H3_EXCESSIVE_LOAD),
                                b"HTTP/3 request budget exhausted",
                            );
                            break;
                        }
                        requests += 1;
                        let permit = match permits.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                state.bans.note_violation(peer.ip(), RULE_H3_EXHAUSTED);
                                connection.close(
                                    quinn::VarInt::from_u32(H3_EXCESSIVE_LOAD),
                                    b"HTTP/3 stream budget exhausted",
                                );
                                break;
                            }
                        };
                        let task_state = state.clone();
                        let task_tls = tls_info.clone();
                        let task_resets = reset_count.clone();
                        tasks.spawn(async move {
                            handle_request(
                                resolver,
                                peer,
                                task_tls,
                                task_state,
                                permit,
                                task_resets,
                            )
                            .await
                        });
                    }
                    Ok(None) => break,
                    Err(error) => {
                        tracing::debug!(error = %error, "HTTP/3 connection closed with an error");
                        break;
                    }
                }
            }
            changed = shutdown.changed() => {
                if (changed.is_err() || *shutdown.borrow()) && !shutting_down {
                    shutting_down = true;
                    shutdown_deadline = Some(Instant::now() + H3_SHUTDOWN_GRACE);
                    let _ = timeout(Duration::from_millis(500), h3_connection.shutdown(0)).await;
                }
            }
            _ = async move {
                match shutdown_wait_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                tracing::warn!("HTTP/3 graceful shutdown deadline reached; closing the connection");
                connection.close(quinn::VarInt::from_u32(0), b"HTTP/3 shutdown deadline reached");
                break;
            }
        }
    }

    let _ = timeout(H3_TASK_DRAIN_GRACE, async {
        while let Some(joined) = tasks.join_next().await {
            let _ = handle_join(
                Some(joined),
                &state,
                peer,
                &tls_info,
                &reset_count,
                limits.max_h3_reset_errors,
            );
        }
    })
    .await;
    tasks.abort_all();
    connection.close(quinn::VarInt::from_u32(0), b"HTTP/3 connection closed");
    Ok(())
}

fn handle_join(
    joined: Option<std::result::Result<StreamOutcome, tokio::task::JoinError>>,
    state: &AppState,
    peer: SocketAddr,
    tls_info: &TlsConnectionInfo,
    reset_count: &std::sync::atomic::AtomicUsize,
    max_resets: usize,
) -> bool {
    match joined {
        Some(Ok(outcome)) if outcome.reset => {
            reset_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1 > max_resets
        }
        Some(Ok(_)) => false,
        Some(Err(error)) => {
            tracing::warn!(error = %error, "HTTP/3 request task failed");
            let reject = H3Reject {
                status: 500,
                rule: RULE_H3_PROTOCOL,
                detail: "HTTP/3 request task terminated unexpectedly".to_string(),
                request_id: next_request_id(),
                method: "-".to_string(),
                path: "/".to_string(),
                client_reset: false,
            };
            record_reject(state, peer, tls_info, &reject);
            false
        }
        None => false,
    }
}

async fn handle_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    peer: SocketAddr,
    tls_info: TlsConnectionInfo,
    state: Arc<AppState>,
    _permit: OwnedSemaphorePermit,
    _reset_count: Arc<std::sync::atomic::AtomicUsize>,
) -> StreamOutcome {
    let started = Instant::now();
    let header_timeout = Duration::from_millis(state.config.limits.header_timeout_ms);
    let resolved = match timeout(header_timeout, resolver.resolve_request()).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            if let Some(authority) = classify_h3_authority_reject(&error) {
                let response_result = if authority.response_sent {
                    "sent"
                } else {
                    "failed"
                };
                let reject = H3Reject {
                    status: 400,
                    rule: authority.rule,
                    detail: format!(
                        "HTTP/3 authority validation failed: h3_authority_error={} response_result={} protocol_error=H3_MESSAGE_ERROR(0x10E) upstream_reached=false",
                        authority.kind, response_result
                    ),
                    request_id: next_request_id(),
                    method: "-".to_string(),
                    path: "/".to_string(),
                    client_reset: !authority.response_sent,
                };
                record_reject(&state, peer, &tls_info, &reject);
                return StreamOutcome {
                    reset: !authority.response_sent,
                };
            }
            let reject = H3Reject {
                status: 400,
                rule: RULE_H3_PROTOCOL,
                detail: format!("HTTP/3 request headers failed: {error}"),
                request_id: next_request_id(),
                method: "-".to_string(),
                path: "/".to_string(),
                client_reset: true,
            };
            record_reject(&state, peer, &tls_info, &reject);
            return StreamOutcome { reset: true };
        }
        Err(_) => {
            let reject = H3Reject {
                status: 408,
                rule: "HW-NATIVE-TIMEOUT-001",
                detail: "HTTP/3 request headers timed out".to_string(),
                request_id: next_request_id(),
                method: "-".to_string(),
                path: "/".to_string(),
                client_reset: true,
            };
            record_reject(&state, peer, &tls_info, &reject);
            return StreamOutcome { reset: true };
        }
    };
    let (request, mut stream) = resolved;
    tracing::trace!(peer = %peer, method = %request.method(), path = %request.uri(), "HTTP/3 request headers resolved");
    let mut request_id = next_request_id();
    let mut method = request.method().as_str().to_string();
    let mut path = request.uri().path().to_string();
    let total_left = Duration::from_millis(state.config.limits.request_total_timeout_ms)
        .saturating_sub(started.elapsed());

    match timeout(
        total_left,
        process_h3_request(
            request,
            &mut stream,
            peer,
            &tls_info,
            state.clone(),
            &mut request_id,
            &mut method,
            &mut path,
        ),
    )
    .await
    {
        Ok(Ok(())) => StreamOutcome { reset: false },
        Ok(Err(reject)) => {
            let sent = send_synthetic(
                &mut stream,
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
            let reject = H3Reject {
                status: 504,
                rule: "HW-NATIVE-TIMEOUT-001",
                detail: "HTTP/3 request timed out".to_string(),
                request_id,
                method,
                path,
                client_reset: false,
            };
            let _ = send_synthetic(
                &mut stream,
                &reject.method,
                504,
                reject.rule,
                &reject.detail,
            )
            .await;
            record_reject(&state, peer, &tls_info, &reject);
            StreamOutcome { reset: false }
        }
    }
}

fn classify_h3_authority_reject(error: &h3::error::StreamError) -> Option<H3AuthorityReject> {
    let h3::error::StreamError::StreamError { reason, .. } = error else {
        return None;
    };
    let details = reason.strip_prefix("h3_authority_error=")?;
    let (kind, remainder) = details.split_once(' ')?;
    let (response_result, protocol_error) = remainder.split_once(' ')?;
    let (rule, kind) = match kind {
        "missing" => (RULE_H3_AUTHORITY_MISSING, "missing"),
        "mismatch" => (RULE_H3_AUTHORITY_MISMATCH, "mismatch"),
        _ => return None,
    };
    let response_sent = match response_result {
        "response_result=sent" => true,
        "response_result=failed" => false,
        _ => return None,
    };
    if protocol_error != "protocol_error=H3_MESSAGE_ERROR(0x10E)" {
        return None;
    }
    Some(H3AuthorityReject {
        rule,
        kind,
        response_sent,
    })
}

#[allow(clippy::too_many_arguments)]
async fn process_h3_request(
    request: http::Request<()>,
    stream: &mut H3Stream,
    peer: SocketAddr,
    tls_info: &TlsConnectionInfo,
    state: Arc<AppState>,
    request_id: &mut u64,
    method_out: &mut String,
    path_out: &mut String,
) -> std::result::Result<(), H3Reject> {
    if request.extensions().get::<h3::ext::Protocol>().is_some() {
        return Err(reject(
            *request_id,
            method_out,
            path_out,
            400,
            RULE_H3_PROTOCOL,
            "extended CONNECT is not accepted",
            false,
        ));
    }
    let (parts, ()) = request.into_parts();
    *method_out = parts.method.as_str().to_string();
    let head = match request_head_from_http_parts(
        &parts.method,
        &parts.uri,
        &parts.headers,
        HttpVersion::Http3,
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
                RULE_H3_PROTOCOL,
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
            RULE_H3_BODY,
            "declared request body exceeds the route limit",
            false,
        ));
    }
    let (body, trailers) = match read_body(stream, body_limit, &state.config.limits).await {
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
                    RULE_H3_CLIENT_RESET
                } else {
                    RULE_H3_BODY
                },
                &error.to_string(),
                client_reset,
            ));
        }
    };
    tracing::trace!(peer = %peer, body_bytes = body.len(), trailers = trailers.len(), "HTTP/3 request body resolved");
    if let Some(length) = head.content_length {
        if length != body.len() as u64 {
            return Err(reject(
                *request_id,
                method_out,
                path_out,
                400,
                RULE_H3_PROTOCOL,
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
    tracing::trace!(peer = %peer, "HTTP/3 request entering gateway");
    let response = process_request(gateway_request, state).await;
    tracing::trace!(peer = %peer, status = response.head.status, "HTTP/3 gateway response ready");
    if let Err(error) = send_gateway_response(stream, &head, &response).await {
        return Err(reject(
            *request_id,
            method_out,
            path_out,
            400,
            RULE_H3_CLIENT_RESET,
            &error.to_string(),
            true,
        ));
    }
    tracing::trace!(peer = %peer, "HTTP/3 response sent");
    Ok(())
}

async fn read_body(
    stream: &mut H3Stream,
    max_bytes: usize,
    limits: &crate::config::LimitsConfig,
) -> std::result::Result<(Vec<u8>, Vec<HeaderField>), (CoreError, bool)> {
    let idle = Duration::from_millis(limits.body_idle_timeout_ms);
    let mut body = Vec::new();
    loop {
        let chunk = match timeout(idle, stream.recv_data()).await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                return Err((
                    CoreError::Protocol(format!("HTTP/3 request stream failed: {error}")),
                    true,
                ))
            }
            Err(_) => {
                return Err((
                    CoreError::Limit("HTTP/3 request body timed out".to_string()),
                    false,
                ))
            }
        };
        let mut chunk = chunk;
        let length = chunk.remaining();
        if body.len().saturating_add(length) > max_bytes {
            return Err((
                CoreError::Limit("HTTP/3 request body exceeds the route limit".to_string()),
                false,
            ));
        }
        let offset = body.len();
        body.resize(offset + length, 0);
        chunk.copy_to_slice(&mut body[offset..]);
    }
    let trailers = match timeout(idle, stream.recv_trailers()).await {
        Ok(Ok(Some(trailers))) => {
            fields_from_http_headers(&trailers, limits).map_err(|error| (error, false))?
        }
        Ok(Ok(None)) => Vec::new(),
        Ok(Err(error)) => {
            return Err((
                CoreError::Protocol(format!("HTTP/3 trailers failed: {error}")),
                true,
            ))
        }
        Err(_) => {
            return Err((
                CoreError::Limit("HTTP/3 request trailers timed out".to_string()),
                false,
            ))
        }
    };
    validate_trailer_fields(&trailers).map_err(|error| (error, false))?;
    Ok((body, trailers))
}

async fn send_gateway_response(
    stream: &mut H3Stream,
    request: &RequestHead,
    response: &GatewayResponse,
) -> Result<()> {
    if (100..200).contains(&response.head.status) {
        return Err(CoreError::Protocol(
            "informational upstream responses are not accepted on HTTP/3".to_string(),
        ));
    }
    let status = StatusCode::from_u16(response.head.status)
        .map_err(|_| CoreError::Protocol("invalid HTTP/3 response status".to_string()))?;
    let no_body =
        request.method == "HEAD" || response.head.status == 204 || response.head.status == 304;
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
        .ok_or_else(|| CoreError::Protocol("cannot build HTTP/3 response".to_string()))? = headers;
    let response_head = builder
        .body(())
        .map_err(|error| CoreError::Protocol(format!("invalid HTTP/3 response: {error}")))?;
    let trailers = if response.trailers.is_empty() || no_body {
        None
    } else {
        validate_trailer_fields(&response.trailers)?;
        Some(fields_to_http_headers(&response.trailers)?)
    };
    stream
        .send_response(response_head)
        .await
        .map_err(|error| CoreError::Protocol(format!("HTTP/3 response headers failed: {error}")))?;
    if !no_body && !response.body.is_empty() {
        stream
            .send_data(Bytes::copy_from_slice(&response.body))
            .await
            .map_err(|error| {
                CoreError::Protocol(format!("HTTP/3 response body failed: {error}"))
            })?;
    }
    if let Some(trailers) = trailers {
        stream
            .send_trailers(trailers)
            .await
            .map_err(|error| CoreError::Protocol(format!("HTTP/3 trailers failed: {error}")))?;
    }
    stream
        .finish()
        .await
        .map_err(|error| CoreError::Protocol(format!("HTTP/3 finish failed: {error}")))?;
    Ok(())
}

async fn send_synthetic(
    stream: &mut H3Stream,
    method: &str,
    status: u16,
    rule: &str,
    detail: &str,
) -> Result<()> {
    let response = GatewayResponse::synthetic(HttpVersion::Http3, status, rule, detail);
    let head = RequestHead {
        method: if method == "HEAD" { "HEAD" } else { "GET" }.to_string(),
        target: "/".to_string(),
        path: "/".to_string(),
        query: None,
        version: HttpVersion::Http3,
        headers: Vec::new(),
        host: String::new(),
        content_length: None,
        chunked: false,
        connection_tokens: Default::default(),
        upgrade: None,
    };
    send_gateway_response(stream, &head, &response).await
}

fn reject(
    request_id: u64,
    method: &str,
    path: &str,
    status: u16,
    rule: &'static str,
    detail: &str,
    client_reset: bool,
) -> H3Reject {
    H3Reject {
        status,
        rule,
        detail: detail.chars().take(200).collect(),
        request_id,
        method: method.to_string(),
        path: path.to_string(),
        client_reset,
    }
}

fn record_reject(
    state: &AppState,
    peer: SocketAddr,
    tls_info: &TlsConnectionInfo,
    reject: &H3Reject,
) {
    let mut event = AuditEvent::new(
        reject.request_id,
        peer.to_string(),
        "h3",
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
