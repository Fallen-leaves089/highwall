use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use ring::rand::{SecureRandom, SystemRandom};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use crate::{
    audit::AuditEvent,
    config::RouteConfig,
    error::{CoreError, Result},
    h1::normalize_authority,
    http::RequestHead,
    policy::{evaluate_request_dlp_blobs, evaluate_response_dlp_blobs, waf_text_layers_rule},
    state::AppState,
    tls::TlsConnectionInfo,
};

pub const RULE_WS_ORIGIN: &str = "HW-NATIVE-WS-003";
pub const RULE_WS_SUBPROTOCOL: &str = "HW-NATIVE-WS-004";
pub const RULE_WS_EXTENSION: &str = "HW-NATIVE-WS-005";
pub const RULE_WS_FRAME: &str = "HW-NATIVE-WS-006";
pub const RULE_WS_MESSAGE_LIMIT: &str = "HW-NATIVE-WS-007";
pub const RULE_WS_RATE: &str = "HW-NATIVE-WS-008";
pub const RULE_WS_CONTENT: &str = "HW-NATIVE-WS-009";

#[derive(Debug, Clone)]
pub struct WsReject {
    pub status: u16,
    pub rule: &'static str,
    pub detail: String,
}

impl WsReject {
    fn new(status: u16, rule: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            rule,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

pub fn validate_upgrade(
    head: &RequestHead,
    route: &RouteConfig,
    secure_transport: bool,
) -> std::result::Result<(), WsReject> {
    let Some(upgrade) = &head.upgrade else {
        return Err(WsReject::new(
            400,
            RULE_WS_FRAME,
            "missing WebSocket upgrade",
        ));
    };
    if upgrade.extensions.is_some() {
        return Err(WsReject::new(
            403,
            RULE_WS_EXTENSION,
            "WebSocket extensions are not accepted on this route",
        ));
    }
    let origin = match upgrade.origin.as_deref() {
        Some(value) => Some(
            parse_origin(value)
                .ok_or_else(|| WsReject::new(403, RULE_WS_ORIGIN, "invalid WebSocket Origin"))?,
        ),
        None => None,
    };
    if route.ws_require_origin && origin.is_none() {
        return Err(WsReject::new(
            403,
            RULE_WS_ORIGIN,
            "WebSocket Origin is required",
        ));
    }
    if let Some(origin) = &origin {
        let explicit = route
            .ws_origins
            .iter()
            .filter_map(|value| parse_origin(value))
            .any(|allowed| same_origin(&allowed, origin));
        let same_site = route.ws_allow_same_origin
            && origin.scheme == if secure_transport { "https" } else { "http" }
            && origin.host.eq_ignore_ascii_case(&head.host)
            && origin_port_matches_host(origin, head);
        if !explicit && !same_site {
            return Err(WsReject::new(
                403,
                RULE_WS_ORIGIN,
                "WebSocket Origin is not allowed",
            ));
        }
    }
    let requested = &upgrade.subprotocols;
    if route.ws_require_subprotocol && requested.is_empty() {
        return Err(WsReject::new(
            403,
            RULE_WS_SUBPROTOCOL,
            "a WebSocket subprotocol is required",
        ));
    }
    if !requested.is_empty() {
        if route.ws_subprotocols.is_empty() {
            return Err(WsReject::new(
                403,
                RULE_WS_SUBPROTOCOL,
                "this route does not allow WebSocket subprotocols",
            ));
        }
        if !requested
            .iter()
            .any(|value| route.ws_subprotocols.iter().any(|allowed| allowed == value))
        {
            return Err(WsReject::new(
                403,
                RULE_WS_SUBPROTOCOL,
                "none of the requested WebSocket subprotocols is allowed",
            ));
        }
    }
    Ok(())
}

pub fn validate_accept(
    head: &RequestHead,
    response: &crate::http::ResponseHead,
    route: &RouteConfig,
) -> bool {
    if response.status != 101 {
        return false;
    }
    let connection_ok = response.header("connection").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    });
    let upgrade_ok = response
        .header("upgrade")
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let Some(request_upgrade) = &head.upgrade else {
        return false;
    };
    let accept_ok = response
        .header("sec-websocket-accept")
        .is_some_and(|value| {
            value.trim() == crate::upstream::websocket_accept_value(&request_upgrade.websocket_key)
        });
    let extension_ok = response.header("sec-websocket-extensions").is_none();
    let selected_protocol = response.header("sec-websocket-protocol");
    let protocol_ok = match selected_protocol {
        None => true,
        Some(selected) => {
            let selected = selected.trim();
            !selected.contains(',')
                && request_upgrade
                    .subprotocols
                    .iter()
                    .any(|requested| requested == selected)
                && route
                    .ws_subprotocols
                    .iter()
                    .any(|allowed| allowed == selected)
        }
    };
    connection_ok && upgrade_ok && accept_ok && extension_ok && protocol_ok
}

fn parse_origin(value: &str) -> Option<Origin> {
    if value.is_empty()
        || value.len() > 512
        || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return None;
    }
    let (scheme, authority) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https")
        || authority.is_empty()
        || authority.contains(['/', '?', '#', '@', '\\'])
        || authority.ends_with('.')
    {
        return None;
    }
    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].parse::<std::net::Ipv6Addr>().ok()?.to_string();
        let suffix = &rest[end + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix
                .strip_prefix(':')?
                .parse::<u16>()
                .ok()
                .filter(|value| *value != 0)?
        };
        (host, port)
    } else {
        if authority.matches(':').count() > 1 {
            return None;
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => (
                normalize_origin_host(host)?,
                port.parse::<u16>().ok().filter(|value| *value != 0)?,
            ),
            None => (normalize_origin_host(authority)?, default_port),
        }
    };
    Some(Origin { scheme, host, port })
}

fn normalize_origin_host(host: &str) -> Option<String> {
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    normalize_authority(host).ok()
}

fn same_origin(a: &Origin, b: &Origin) -> bool {
    a.scheme == b.scheme && a.host.eq_ignore_ascii_case(&b.host) && a.port == b.port
}

fn origin_port_matches_host(origin: &Origin, head: &RequestHead) -> bool {
    let Some(host_header) = head.header("host") else {
        return false;
    };
    let explicit = if let Some(rest) = host_header.trim().strip_prefix('[') {
        rest.find(']')
            .and_then(|end| rest[end + 1..].strip_prefix(':'))
            .and_then(|port| port.parse::<u16>().ok())
    } else {
        host_header
            .trim()
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
    };
    match explicit {
        Some(port) => origin.port == port,
        None => origin.port == if origin.scheme == "https" { 443 } else { 80 },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Reserved(u8),
}

impl Opcode {
    fn from_byte(value: u8) -> Self {
        match value {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xa => Self::Pong,
            other => Self::Reserved(other),
        }
    }

    fn is_control(self) -> bool {
        matches!(
            self,
            Self::Close | Self::Ping | Self::Pong | Self::Reserved(0xb..=0xf)
        )
    }

    fn byte(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xa,
            Self::Reserved(value) => value,
        }
    }
}

#[derive(Debug)]
struct Frame {
    fin: bool,
    opcode: Opcode,
    payload: Vec<u8>,
    raw: Vec<u8>,
}

struct Message {
    opcode: Opcode,
    payload: Vec<u8>,
}

struct Runtime {
    state: Arc<AppState>,
    route: RouteConfig,
    request_id: u64,
    peer: SocketAddr,
    path: String,
    tls: TlsConnectionInfo,
}

enum PumpEnd {
    Closed,
}

#[derive(Debug)]
struct FrameError {
    rule: &'static str,
    detail: String,
    close_code: u16,
}

#[allow(clippy::too_many_arguments)]
pub async fn proxy<C, U>(
    client: C,
    upstream: U,
    state: Arc<AppState>,
    route: RouteConfig,
    request_id: u64,
    peer: SocketAddr,
    path: String,
    tls: TlsConnectionInfo,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let runtime = Arc::new(Runtime {
        state,
        route,
        request_id,
        peer,
        path,
        tls,
    });
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let client_to_upstream = pump(client_read, upstream_write, true, runtime.clone());
    let upstream_to_client = pump(upstream_read, client_write, false, runtime);
    tokio::pin!(client_to_upstream);
    tokio::pin!(upstream_to_client);
    let result = tokio::select! {
        result = &mut client_to_upstream => result,
        result = &mut upstream_to_client => result,
    };
    result.map(|_| ())
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    source_is_client: bool,
    runtime: Arc<Runtime>,
) -> Result<PumpEnd>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let limits = &runtime.state.config.limits;
    let mut message: Option<Message> = None;
    let mut tokens = limits.max_ws_messages_per_second as f64;
    let mut last = Instant::now();
    loop {
        let frame = match read_frame(
            &mut reader,
            source_is_client,
            limits.max_ws_frame_bytes,
            Duration::from_millis(limits.max_ws_idle_timeout_ms),
        )
        .await
        {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(PumpEnd::Closed),
            Err(error) => {
                audit_ws_violation(&runtime, error.rule, &error.detail);
                let _ = write_close(
                    &mut writer,
                    error.close_code,
                    error.detail.as_bytes(),
                    source_is_client,
                )
                .await;
                return Err(CoreError::Protocol(error.detail));
            }
        };
        if frame.opcode.is_control() {
            match frame.opcode {
                Opcode::Close => {
                    validate_close_payload(&frame.payload)?;
                    writer.write_all(&frame.raw).await?;
                    writer.flush().await?;
                    return Ok(PumpEnd::Closed);
                }
                Opcode::Ping | Opcode::Pong => {
                    writer.write_all(&frame.raw).await?;
                    writer.flush().await?;
                    continue;
                }
                Opcode::Reserved(_) => {
                    let message = "reserved WebSocket control opcode";
                    let _ =
                        write_close(&mut writer, 1002, message.as_bytes(), source_is_client).await;
                    return Err(CoreError::Protocol(message.to_string()));
                }
                _ => unreachable!("control opcode classification"),
            }
        }
        if matches!(frame.opcode, Opcode::Reserved(_)) {
            let message = "reserved WebSocket data opcode";
            let _ = write_close(&mut writer, 1002, message.as_bytes(), source_is_client).await;
            return Err(CoreError::Protocol(message.to_string()));
        }
        let opcode = match frame.opcode {
            Opcode::Continuation => match message.as_ref() {
                Some(message) => message.opcode,
                None => {
                    let message = "continuation frame without an open message";
                    let _ =
                        write_close(&mut writer, 1002, message.as_bytes(), source_is_client).await;
                    return Err(CoreError::Protocol(message.to_string()));
                }
            },
            Opcode::Text | Opcode::Binary => {
                if message.is_some() {
                    let detail = "new data frame before fragmented message completed";
                    let _ =
                        write_close(&mut writer, 1002, detail.as_bytes(), source_is_client).await;
                    return Err(CoreError::Protocol(detail.to_string()));
                }
                frame.opcode
            }
            _ => unreachable!("control opcodes handled above"),
        };
        let now = Instant::now();
        tokens = (tokens
            + now.duration_since(last).as_secs_f64() * limits.max_ws_messages_per_second as f64)
            .min(limits.max_ws_messages_per_second as f64);
        last = now;
        if tokens < 1.0 {
            audit_ws_violation(&runtime, RULE_WS_RATE, "WebSocket message rate exceeded");
            let _ = write_close(
                &mut writer,
                1008,
                b"message rate exceeded",
                source_is_client,
            )
            .await;
            return Err(CoreError::Limit(
                "WebSocket message rate exceeded".to_string(),
            ));
        }
        tokens -= 1.0;
        let message_state = message.get_or_insert_with(|| Message {
            opcode,
            payload: Vec::new(),
        });
        if message_state
            .payload
            .len()
            .saturating_add(frame.payload.len())
            > limits.max_ws_message_bytes
        {
            audit_ws_violation(
                &runtime,
                RULE_WS_MESSAGE_LIMIT,
                "WebSocket message exceeded the configured limit",
            );
            let _ = write_close(&mut writer, 1009, b"message too large", source_is_client).await;
            return Err(CoreError::Limit(
                "WebSocket message exceeds the configured limit".to_string(),
            ));
        }
        message_state.payload.extend_from_slice(&frame.payload);
        if !frame.fin {
            continue;
        }
        let complete = message.take().expect("message exists");
        if complete.opcode == Opcode::Text {
            if let Err(error) = std::str::from_utf8(&complete.payload) {
                let _ = write_close(&mut writer, 1007, b"invalid UTF-8", source_is_client).await;
                return Err(CoreError::Protocol(format!(
                    "invalid UTF-8 WebSocket text message: {error}"
                )));
            }
        }
        if let Some(rule) = inspect_message(&runtime, source_is_client, &complete) {
            audit_ws_violation(
                &runtime,
                &rule,
                "WebSocket message blocked by content policy",
            );
            let _ = write_close(&mut writer, 1008, b"message blocked", source_is_client).await;
            return Err(CoreError::Denied(format!(
                "WebSocket message blocked by {rule}"
            )));
        }
        write_frame(
            &mut writer,
            true,
            complete.opcode,
            &complete.payload,
            source_is_client,
        )
        .await?;
    }
}

fn inspect_message(runtime: &Runtime, source_is_client: bool, message: &Message) -> Option<String> {
    if !runtime.route.ws_inspect_messages {
        return None;
    }
    let config = &runtime.state.config;
    if runtime.route.waf
        && config.policy.waf.enabled
        && config.policy.waf.inspect_body_text
        && message.opcode == Opcode::Text
    {
        if let Some(rule) = waf_text_layers_rule(&String::from_utf8_lossy(&message.payload)) {
            return Some(rule);
        }
    }
    if runtime.route.dlp && config.policy.dlp.enabled {
        let blobs = std::slice::from_ref(&message.payload);
        let rule = if source_is_client {
            evaluate_request_dlp_blobs(config, &runtime.route, blobs)
        } else {
            evaluate_response_dlp_blobs(config, &runtime.route, blobs)
        };
        if let Some(rule) = rule {
            return Some(rule.to_string());
        }
    }
    None
}

fn audit_ws_violation(runtime: &Runtime, rule: &str, detail: &str) {
    let mut event = AuditEvent::new(
        runtime.request_id,
        runtime.peer.to_string(),
        "websocket",
        "GET",
        &runtime.path,
        &runtime.route.name,
        "deny",
        1008,
    );
    event.rule_ids = vec![rule.to_string()];
    event.detail = Some(detail.to_string());
    event.tls_server_name = runtime.tls.server_name.clone();
    event.tls_version = runtime.tls.version.clone();
    event.alpn = runtime.tls.alpn.clone();
    let _ = runtime.state.audit.record(event);
}

async fn read_frame<R>(
    reader: &mut R,
    source_is_client: bool,
    max_frame: usize,
    idle: Duration,
) -> std::result::Result<Option<Frame>, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    let first = match timeout(idle, reader.read(&mut header[..1])).await {
        Ok(Ok(0)) => return Ok(None),
        Ok(Ok(1)) => header[0],
        Ok(Ok(_)) => unreachable!("single-byte read"),
        Ok(Err(error)) => {
            return Err(FrameError {
                rule: RULE_WS_FRAME,
                detail: format!("WebSocket read failed: {error}"),
                close_code: 1002,
            });
        }
        Err(_) => {
            return Err(FrameError {
                rule: RULE_WS_FRAME,
                detail: "WebSocket idle timeout".to_string(),
                close_code: 1001,
            });
        }
    };
    read_exact_with_timeout(reader, &mut header[1..], idle, RULE_WS_FRAME).await?;
    let fin = first & 0x80 != 0;
    if first & 0x70 != 0 {
        return Err(FrameError {
            rule: RULE_WS_FRAME,
            detail: "WebSocket RSV bits require an unsupported extension".to_string(),
            close_code: 1002,
        });
    }
    let opcode = Opcode::from_byte(first & 0x0f);
    let masked = header[1] & 0x80 != 0;
    if source_is_client != masked {
        return Err(FrameError {
            rule: RULE_WS_FRAME,
            detail: if source_is_client {
                "client WebSocket frame is not masked".to_string()
            } else {
                "server WebSocket frame is masked".to_string()
            },
            close_code: 1002,
        });
    }
    let length_code = header[1] & 0x7f;
    let mut header_bytes = header.to_vec();
    let length = match length_code {
        0..=125 => length_code as u64,
        126 => {
            let mut bytes = [0_u8; 2];
            read_exact_with_timeout(reader, &mut bytes, idle, RULE_WS_FRAME).await?;
            header_bytes.extend_from_slice(&bytes);
            let value = u16::from_be_bytes(bytes) as u64;
            if value < 126 {
                return Err(FrameError {
                    rule: RULE_WS_FRAME,
                    detail: "non-canonical WebSocket length encoding".to_string(),
                    close_code: 1002,
                });
            }
            value
        }
        127 => {
            let mut bytes = [0_u8; 8];
            read_exact_with_timeout(reader, &mut bytes, idle, RULE_WS_FRAME).await?;
            header_bytes.extend_from_slice(&bytes);
            let value = u64::from_be_bytes(bytes);
            if value < 65_536 || value & (1_u64 << 63) != 0 {
                return Err(FrameError {
                    rule: RULE_WS_FRAME,
                    detail: "invalid WebSocket 64-bit length".to_string(),
                    close_code: 1002,
                });
            }
            value
        }
        _ => unreachable!("7-bit length"),
    };
    if opcode.is_control() && (!fin || length > 125) {
        return Err(FrameError {
            rule: RULE_WS_FRAME,
            detail: "invalid fragmented or oversized WebSocket control frame".to_string(),
            close_code: 1002,
        });
    }
    let length = usize::try_from(length).map_err(|_| FrameError {
        rule: RULE_WS_MESSAGE_LIMIT,
        detail: "WebSocket frame length does not fit memory".to_string(),
        close_code: 1009,
    })?;
    if length > max_frame {
        return Err(FrameError {
            rule: RULE_WS_MESSAGE_LIMIT,
            detail: "WebSocket frame exceeds the configured limit".to_string(),
            close_code: 1009,
        });
    }
    let mut mask = [0_u8; 4];
    if masked {
        read_exact_with_timeout(reader, &mut mask, idle, RULE_WS_FRAME).await?;
        header_bytes.extend_from_slice(&mask);
    }
    let mut payload = vec![0_u8; length];
    read_exact_with_timeout(reader, &mut payload, idle, RULE_WS_FRAME).await?;
    let mut raw = header_bytes;
    raw.extend_from_slice(&payload);
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok(Some(Frame {
        fin,
        opcode,
        payload,
        raw,
    }))
}

async fn read_exact_with_timeout<R>(
    reader: &mut R,
    buffer: &mut [u8],
    idle: Duration,
    rule: &'static str,
) -> std::result::Result<(), FrameError>
where
    R: AsyncRead + Unpin,
{
    match timeout(idle, reader.read_exact(buffer)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(FrameError {
            rule,
            detail: format!("truncated WebSocket frame: {error}"),
            close_code: 1002,
        }),
        Err(_) => Err(FrameError {
            rule,
            detail: "WebSocket frame timeout".to_string(),
            close_code: 1008,
        }),
    }
}

async fn write_frame<W>(
    writer: &mut W,
    fin: bool,
    opcode: Opcode,
    payload: &[u8],
    masked: bool,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut frame = Vec::with_capacity(payload.len().saturating_add(14));
    frame.push((if fin { 0x80 } else { 0 }) | opcode.byte());
    let mask_bit = if masked { 0x80 } else { 0 };
    if payload.len() <= 125 {
        frame.push(mask_bit | payload.len() as u8);
    } else if payload.len() <= u16::MAX as usize {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(mask_bit | 127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    if masked {
        let mut mask = [0_u8; 4];
        SystemRandom::new()
            .fill(&mut mask)
            .map_err(|_| CoreError::Protocol("WebSocket mask generation failed".to_string()))?;
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
    } else {
        frame.extend_from_slice(payload);
    }
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_close<W>(writer: &mut W, code: u16, reason: &[u8], masked: bool) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut payload = Vec::with_capacity(2 + reason.len().min(123));
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(&reason[..reason.len().min(123)]);
    write_frame(writer, true, Opcode::Close, &payload, masked).await
}

fn validate_close_payload(payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }
    if payload.len() == 1 {
        return Err(CoreError::Protocol(
            "WebSocket close payload must be empty or contain a status code".to_string(),
        ));
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    if !matches!(code, 1000..=1014 | 3000..=4999) || matches!(code, 1004..=1006 | 1015) {
        return Err(CoreError::Protocol(format!(
            "invalid WebSocket close code: {code}"
        )));
    }
    std::str::from_utf8(&payload[2..])
        .map_err(|error| CoreError::Protocol(format!("invalid WebSocket close reason: {error}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_matching_is_strict_about_scheme_and_port() {
        let origin = parse_origin("https://example.test").unwrap();
        assert_eq!(origin.port, 443);
        assert!(parse_origin("https://example.test/path").is_none());
        assert!(parse_origin("javascript:alert(1)").is_none());
        assert!(!same_origin(
            &origin,
            &parse_origin("http://example.test").unwrap()
        ));
        assert!(!same_origin(
            &origin,
            &parse_origin("https://example.test:8443").unwrap()
        ));
    }

    #[tokio::test]
    async fn client_frames_must_be_masked_and_bounded() {
        let unmasked = [0x81_u8, 0x01, b'a'];
        let error = read_frame(&mut &unmasked[..], true, 1024, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(error.close_code, 1002);
        let oversized = [0x81_u8, 0x7e, 0x02, 0x00];
        let error = read_frame(&mut &oversized[..], false, 16, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(error.close_code, 1009);
    }

    #[tokio::test]
    async fn masked_text_frame_is_unmasked_after_parsing() {
        let frame = [
            0x81_u8,
            0x85,
            1,
            2,
            3,
            4,
            b'a' ^ 1,
            b'b' ^ 2,
            b'c' ^ 3,
            b'd' ^ 4,
            b'e' ^ 1,
        ];
        let parsed = read_frame(&mut &frame[..], true, 1024, Duration::from_secs(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(parsed.payload, b"abcde");
        assert_eq!(parsed.opcode, Opcode::Text);
    }
}
