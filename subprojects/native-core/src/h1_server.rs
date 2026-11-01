use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    time::{timeout, Instant},
};

use crate::{
    audit::{next_request_id, normalized_path, AuditEvent},
    error::{CoreError, Result},
    gateway::{first_rule, hash_text, is_enforcement_rule, GatewayRequest, GatewayResponse},
    h1::{read_request_body, read_request_head},
    http::{HttpVersion, RequestHead},
    policy::{evaluate_request, select_route, PolicyAction, RequestContext, RULE_AGENT, RULE_BAN},
    state::AppState,
    tls::TlsConnectionInfo,
    upstream::{build_h1_request, is_hop_by_hop, UpstreamTarget},
    ws,
};

pub async fn serve_connection<S>(
    stream: S,
    peer: SocketAddr,
    tls_info: TlsConnectionInfo,
    state: Arc<AppState>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut reader = BufReader::new(stream);
    let max_requests = state.config.limits.max_requests_per_connection.max(1);
    for request_index in 0..max_requests {
        let started = Instant::now();
        let head = match timeout(
            Duration::from_millis(state.config.limits.header_timeout_ms),
            read_request_head(&mut reader, &state.config.limits),
        )
        .await
        {
            Ok(Ok(Some(head))) => head,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(error)) => {
                let status = protocol_error_status(&error);
                let _ = send_simple(
                    reader.get_mut(),
                    status,
                    "HW-NATIVE-PROTOCOL-001",
                    "request head was rejected",
                )
                .await;
                record_protocol_error(&state, peer, &tls_info, status, "HW-NATIVE-PROTOCOL-001");
                return Err(error);
            }
            Err(_) => {
                let _ = send_simple(
                    reader.get_mut(),
                    408,
                    "HW-NATIVE-TIMEOUT-001",
                    "request head timed out",
                )
                .await;
                record_protocol_error(&state, peer, &tls_info, 408, "HW-NATIVE-TIMEOUT-001");
                return Ok(());
            }
        };

        let request_id = next_request_id();
        let path_for_audit = normalized_path(&head.target);
        let selected_route = select_route(&state.config, &head);
        let route_name = selected_route
            .as_ref()
            .map(|route| route.name.clone())
            .unwrap_or_else(|| "unmatched".to_string());
        let route_limit = selected_route
            .and_then(|route| route.max_body_bytes)
            .unwrap_or(state.config.limits.max_body_bytes);
        let body = match timeout(
            Duration::from_millis(state.config.limits.body_idle_timeout_ms),
            read_request_body(&mut reader, &head, route_limit),
        )
        .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(error)) => {
                let status = protocol_error_status(&error);
                let _ = send_simple(
                    reader.get_mut(),
                    status,
                    "HW-NATIVE-PROTOCOL-002",
                    "request body was rejected",
                )
                .await;
                record_h1_reject(
                    &state,
                    request_id,
                    peer,
                    &tls_info,
                    &head,
                    &path_for_audit,
                    &route_name,
                    status,
                    "HW-NATIVE-PROTOCOL-002",
                    0,
                );
                return Ok(());
            }
            Err(_) => {
                let _ = send_simple(
                    reader.get_mut(),
                    408,
                    "HW-NATIVE-TIMEOUT-002",
                    "request body timed out",
                )
                .await;
                record_h1_reject(
                    &state,
                    request_id,
                    peer,
                    &tls_info,
                    &head,
                    &path_for_audit,
                    &route_name,
                    408,
                    "HW-NATIVE-TIMEOUT-002",
                    0,
                );
                return Ok(());
            }
        };

        if head.upgrade.is_some() {
            return serve_websocket(
                reader,
                head,
                body,
                peer,
                tls_info,
                state,
                request_id,
                path_for_audit,
                route_name,
                started,
            )
            .await;
        }

        let keep_alive_by_request =
            should_keep_alive_request(&head, request_index + 1 < max_requests);
        let audit_head = head.clone();
        let audit_body_len = body.len();
        let request = GatewayRequest {
            request_id,
            head,
            body,
            trailers: Vec::new(),
            peer,
            tls: tls_info.clone(),
            secure_transport: tls_info.version.is_some(),
        };
        let total_left = Duration::from_millis(state.config.limits.request_total_timeout_ms)
            .saturating_sub(started.elapsed());
        let response = match timeout(
            total_left,
            crate::gateway::process_request(request, state.clone()),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => {
                let mut event = AuditEvent::new(
                    request_id,
                    peer.to_string(),
                    audit_head.version.as_str(),
                    &audit_head.method,
                    &path_for_audit,
                    &route_name,
                    "deny",
                    504,
                );
                event.rule_ids = vec!["HW-NATIVE-TIMEOUT-001".to_string()];
                event.bytes_in = audit_body_len as u64;
                event.tls_server_name = tls_info.server_name.clone();
                event.tls_version = tls_info.version.clone();
                event.alpn = tls_info.alpn.clone();
                let _ = state.audit.record(event);
                GatewayResponse::synthetic(
                    audit_head.version,
                    504,
                    "HW-NATIVE-TIMEOUT-001",
                    "request timed out",
                )
            }
        };
        let keep_alive = keep_alive_by_request && !response.head.connection_close;
        write_response(reader.get_mut(), &audit_head, &response, keep_alive).await?;
        if !keep_alive {
            return Ok(());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_websocket<S>(
    reader: BufReader<S>,
    head: RequestHead,
    body: Vec<u8>,
    peer: SocketAddr,
    tls_info: TlsConnectionInfo,
    state: Arc<AppState>,
    request_id: u64,
    path: String,
    route_name: String,
    started: Instant,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut reader = reader;
    let banned = state.bans.is_banned(peer.ip());
    let agent = state.agent.observe(
        peer.ip(),
        hash_text(&head.path),
        hash_text(&head.method),
        head.header("user-agent").map(hash_text),
    );
    let decision = evaluate_request(
        &state.config,
        &RequestContext {
            head: &head,
            body: &body,
            inspected_body: None,
            trailers: &[],
            banned_rule: banned,
            agent_anomalous: agent.anomalous,
            agent_confirmed: agent.confirmed,
        },
    );
    let route_name = decision
        .route
        .as_ref()
        .map(|route| route.name.clone())
        .unwrap_or(route_name);

    let mut accepted = AuditEvent::new(
        request_id,
        peer.to_string(),
        head.version.as_str(),
        &head.method,
        &path,
        &route_name,
        "accepted",
        0,
    );
    accepted.rule_ids = decision.rule_ids.clone();
    accepted.bytes_in = body.len() as u64;
    accepted.tls_server_name = tls_info.server_name.clone();
    accepted.tls_version = tls_info.version.clone();
    accepted.alpn = tls_info.alpn.clone();
    if !state.audit.record(accepted) {
        send_simple(
            reader.get_mut(),
            503,
            "HW-NATIVE-AUDIT-001",
            "audit unavailable",
        )
        .await?;
        return Ok(());
    }

    if decision.action != PolicyAction::Allow {
        if is_enforcement_rule(&decision) {
            state
                .bans
                .note_violation(peer.ip(), first_rule(&decision.rule_ids));
        }
        let policy_headers = if first_rule(&decision.rule_ids) == RULE_BAN {
            state
                .bans
                .remaining(peer.ip())
                .map(|remaining| {
                    format!(
                        "Retry-After: {}\r\nX-RateLimit-Policy: highwall-source-ban\r\n",
                        remaining.as_secs().max(1)
                    )
                })
                .unwrap_or_default()
        } else {
            String::new()
        };
        send_simple_with_policy_headers(
            reader.get_mut(),
            decision.status,
            first_rule(&decision.rule_ids),
            &decision.reason,
            &policy_headers,
        )
        .await?;
        record_h1_reject(
            &state,
            request_id,
            peer,
            &tls_info,
            &head,
            &path,
            &route_name,
            decision.status,
            first_rule(&decision.rule_ids),
            body.len(),
        );
        return Ok(());
    }

    if !state.rate.check(peer.ip()).permit {
        send_simple(reader.get_mut(), 429, RULE_AGENT, "request rate exceeded").await?;
        record_h1_reject(
            &state,
            request_id,
            peer,
            &tls_info,
            &head,
            &path,
            &route_name,
            429,
            RULE_AGENT,
            body.len(),
        );
        return Ok(());
    }

    let Some(route) = decision.route.clone() else {
        return Err(CoreError::Denied("route disappeared".to_string()));
    };
    if let Err(reject) = ws::validate_upgrade(&head, &route, tls_info.version.is_some()) {
        send_simple(reader.get_mut(), reject.status, reject.rule, &reject.detail).await?;
        state.bans.note_violation(peer.ip(), reject.rule);
        record_h1_reject(
            &state,
            request_id,
            peer,
            &tls_info,
            &head,
            &path,
            &route_name,
            reject.status,
            reject.rule,
            body.len(),
        );
        return Ok(());
    }

    let target = UpstreamTarget::from_config(&state.config, &route);
    let upstream = match target.connect(&state.config).await {
        Ok(stream) => stream,
        Err(_) => {
            send_simple(
                reader.get_mut(),
                502,
                "HW-NATIVE-UPSTREAM-001",
                "upstream unavailable",
            )
            .await?;
            record_h1_reject(
                &state,
                request_id,
                peer,
                &tls_info,
                &head,
                &path,
                &route_name,
                502,
                "HW-NATIVE-UPSTREAM-001",
                body.len(),
            );
            return Ok(());
        }
    };
    let raw = build_h1_request(
        &head,
        &body,
        peer,
        request_id,
        &target,
        if tls_info.version.is_some() {
            "https"
        } else {
            "http"
        },
    );
    let (upstream_reader, response, _) =
        match crate::upstream::exchange_h1(upstream, &raw, &head.method, &state.config).await {
            Ok(value) => value,
            Err(_) => {
                send_simple(
                    reader.get_mut(),
                    502,
                    "HW-NATIVE-UPSTREAM-002",
                    "upstream request failed",
                )
                .await?;
                record_h1_reject(
                    &state,
                    request_id,
                    peer,
                    &tls_info,
                    &head,
                    &path,
                    &route_name,
                    502,
                    "HW-NATIVE-UPSTREAM-002",
                    body.len(),
                );
                return Ok(());
            }
        };
    if !ws::validate_accept(&head, &response, &route) {
        send_simple(
            reader.get_mut(),
            502,
            "HW-NATIVE-WS-002",
            "invalid upstream WebSocket handshake",
        )
        .await?;
        record_h1_reject(
            &state,
            request_id,
            peer,
            &tls_info,
            &head,
            &path,
            &route_name,
            502,
            "HW-NATIVE-WS-002",
            body.len(),
        );
        return Ok(());
    }

    let mut upgrade_response = Vec::new();
    upgrade_response.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
    upgrade_response.extend_from_slice(b"Connection: Upgrade\r\nUpgrade: websocket\r\n");
    if let Some(accept) = response.header("sec-websocket-accept") {
        upgrade_response.extend_from_slice(b"Sec-WebSocket-Accept: ");
        upgrade_response.extend_from_slice(accept.trim().as_bytes());
        upgrade_response.extend_from_slice(b"\r\n");
    }
    if let Some(protocol) = response.header("sec-websocket-protocol") {
        upgrade_response.extend_from_slice(b"Sec-WebSocket-Protocol: ");
        upgrade_response.extend_from_slice(protocol.trim().as_bytes());
        upgrade_response.extend_from_slice(b"\r\n");
    }
    upgrade_response.extend_from_slice(b"\r\n");

    let client_prefix = reader.buffer().to_vec();
    let mut client = crate::io_util::PrefixedStream::new(client_prefix, reader.into_inner());
    client.write_all(&upgrade_response).await?;
    client.flush().await?;
    let upstream_prefix = upstream_reader.buffer().to_vec();
    let upstream =
        crate::io_util::PrefixedStream::new(upstream_prefix, upstream_reader.into_inner());

    let mut completed = AuditEvent::new(
        request_id,
        peer.to_string(),
        "websocket",
        "GET",
        &path,
        &route_name,
        "allow",
        101,
    );
    completed.bytes_in = body.len() as u64;
    completed.bytes_out = upgrade_response.len() as u64;
    completed.tls_server_name = tls_info.server_name.clone();
    completed.tls_version = tls_info.version.clone();
    completed.alpn = tls_info.alpn.clone();
    completed.duration_ms = started.elapsed().as_millis() as u64;
    let _ = state.audit.record(completed);

    if let Err(error) = ws::proxy(
        client, upstream, state, route, request_id, peer, path, tls_info,
    )
    .await
    {
        tracing::debug!(error = %error, "WebSocket proxy connection ended");
    }
    Ok(())
}

async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request: &RequestHead,
    response: &GatewayResponse,
    keep_alive: bool,
) -> Result<usize> {
    let reason = sanitize_reason(&response.head.reason, response.head.status);
    let version = if request.version == HttpVersion::Http10 {
        "HTTP/1.0"
    } else {
        "HTTP/1.1"
    };
    let mut output = Vec::with_capacity(512 + response.body.len());
    output.extend_from_slice(format!("{version} {} {reason}\r\n", response.head.status).as_bytes());
    for header in &response.head.headers {
        if is_hop_by_hop(&header.name)
            || header.name == "content-length"
            || header.name == "transfer-encoding"
        {
            continue;
        }
        output.extend_from_slice(header.name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(header.value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    let no_body = request.method == "HEAD"
        || response.head.status == 204
        || response.head.status == 304
        || (100..200).contains(&response.head.status);
    if response.head.status != 204 && response.head.status != 304 {
        let content_length = if request.method == "HEAD" {
            response
                .head
                .content_length
                .unwrap_or(response.body.len() as u64)
        } else {
            response.body.len() as u64
        };
        output.extend_from_slice(format!("Content-Length: {content_length}\r\n").as_bytes());
    }
    output.extend_from_slice(if keep_alive {
        b"Connection: keep-alive\r\n\r\n"
    } else {
        b"Connection: close\r\n\r\n"
    });
    if !no_body {
        output.extend_from_slice(&response.body);
    }
    writer.write_all(&output).await?;
    writer.flush().await?;
    Ok(output.len())
}

async fn send_simple<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    rule: &str,
    message: &str,
) -> Result<()> {
    send_simple_with_policy_headers(writer, status, rule, message, "").await
}

async fn send_simple_with_policy_headers<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: u16,
    rule: &str,
    message: &str,
    extra_headers: &str,
) -> Result<()> {
    let reason = status_reason(status);
    let body = serde_json::json!({
        "error": if status >= 500 { "request could not be completed" } else { "request rejected" },
        "rule": rule,
        "detail": message.chars().take(200).collect::<String>(),
    })
    .to_string();
    let rate_limit_headers = if status == 429 {
        "Retry-After: 60\r\nX-RateLimit-Policy: highwall-automation-budget\r\n"
    } else {
        extra_headers
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n{rate_limit_headers}X-Content-Type-Options: nosniff\r\n\r\n{}",
        body.len(),
        body
    );
    writer.write_all(response.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

fn should_keep_alive_request(head: &RequestHead, below_limit: bool) -> bool {
    if !below_limit || head.connection_tokens.contains("close") {
        return false;
    }
    if head.version == HttpVersion::Http10 {
        head.connection_tokens.contains("keep-alive")
    } else {
        true
    }
}

fn protocol_error_status(error: &CoreError) -> u16 {
    match error {
        CoreError::Limit(_) => 413,
        CoreError::AuditUnavailable => 503,
        _ => 400,
    }
}

fn status_reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        451 => "Unavailable For Legal Reasons",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

fn sanitize_reason(reason: &str, status: u16) -> String {
    if reason.is_empty() || reason.bytes().any(|byte| byte.is_ascii_control()) {
        status.to_string()
    } else {
        reason.chars().take(128).collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn record_h1_reject(
    state: &AppState,
    request_id: u64,
    peer: SocketAddr,
    tls_info: &TlsConnectionInfo,
    head: &RequestHead,
    path: &str,
    route: &str,
    status: u16,
    rule: &str,
    bytes_in: usize,
) {
    let mut event = AuditEvent::new(
        request_id,
        peer.to_string(),
        head.version.as_str(),
        &head.method,
        path,
        route,
        "deny",
        status,
    );
    event.rule_ids = vec![rule.to_string()];
    event.bytes_in = bytes_in as u64;
    event.tls_server_name = tls_info.server_name.clone();
    event.tls_version = tls_info.version.clone();
    event.alpn = tls_info.alpn.clone();
    let _ = state.audit.record(event);
}

fn record_protocol_error(
    state: &AppState,
    peer: SocketAddr,
    tls_info: &TlsConnectionInfo,
    status: u16,
    rule: &str,
) {
    let mut event = AuditEvent::new(
        next_request_id(),
        peer.to_string(),
        "h1",
        "-",
        "/",
        "unmatched",
        "deny",
        status,
    );
    event.rule_ids = vec![rule.to_string()];
    event.tls_server_name = tls_info.server_name.clone();
    event.tls_version = tls_info.version.clone();
    event.alpn = tls_info.alpn.clone();
    let _ = state.audit.record(event);
}
