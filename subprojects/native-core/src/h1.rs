use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

use crate::{
    config::{is_token_byte, LimitsConfig},
    error::{CoreError, Result},
    http::{
        header_tokens, split_target, HeaderField, HttpVersion, RequestHead, ResponseHead,
        UpgradeRequest,
    },
    policy::valid_websocket_key,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    None,
    ContentLength(u64),
    Chunked,
    UntilEof,
}

pub async fn read_request_head<R>(
    reader: &mut BufReader<R>,
    limits: &LimitsConfig,
) -> Result<Option<RequestHead>>
where
    R: AsyncRead + Unpin,
{
    let Some(block) = read_head_block(reader, limits).await? else {
        return Ok(None);
    };
    parse_request_head(&block, limits).map(Some)
}

pub async fn read_response_head<R>(
    reader: &mut BufReader<R>,
    limits: &LimitsConfig,
) -> Result<ResponseHead>
where
    R: AsyncRead + Unpin,
{
    loop {
        let block = read_head_block(reader, limits).await?.ok_or_else(|| {
            CoreError::Upstream("upstream closed before response headers".to_string())
        })?;
        let response = parse_response_head(&block, limits)?;
        if (100..200).contains(&response.status) {
            if response.status == 101 {
                return Ok(response);
            }
            continue;
        }
        return Ok(response);
    }
}

async fn read_head_block<R>(
    reader: &mut BufReader<R>,
    limits: &LimitsConfig,
) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut block = Vec::with_capacity(1024);
    let mut saw_any = false;
    loop {
        let Some(line) = read_line(reader, limits.max_header_line_bytes).await? else {
            if !saw_any {
                return Ok(None);
            }
            return Err(CoreError::Protocol(
                "connection ended before request head completed".to_string(),
            ));
        };
        saw_any = true;
        if block.len().saturating_add(line.len()) > limits.max_head_bytes {
            return Err(CoreError::Limit(
                "request/response head exceeds configured limit".to_string(),
            ));
        }
        let empty = line == b"\r\n";
        block.extend_from_slice(&line);
        if empty {
            return Ok(Some(block));
        }
    }
}

async fn read_line<R>(reader: &mut R, max: usize) -> Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::with_capacity(128);
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err(CoreError::Protocol(
                "bare end of stream inside a header line".to_string(),
            ));
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(buffer.len(), |index| index + 1);
        if line.len().saturating_add(take) > max.saturating_add(2) {
            return Err(CoreError::Limit(
                "HTTP line exceeds configured limit".to_string(),
            ));
        }
        line.extend_from_slice(&buffer[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    if !line.ends_with(b"\r\n") {
        return Err(CoreError::Protocol("bare LF is not accepted".to_string()));
    }
    if line.len() > 2 && line[..line.len() - 2].contains(&b'\r') {
        return Err(CoreError::Protocol("bare CR is not accepted".to_string()));
    }
    Ok(Some(line))
}

pub fn parse_request_head(block: &[u8], limits: &LimitsConfig) -> Result<RequestHead> {
    if block.starts_with(b"PRI * HTTP/2.0") {
        return Err(CoreError::Protocol(
            "HTTP/2 preface is not accepted on the H1 listener".to_string(),
        ));
    }
    let mut lines = split_crlf(block)?;
    let request_line = lines
        .next()
        .ok_or_else(|| CoreError::Protocol("empty request head".to_string()))?;
    let request_line = std::str::from_utf8(request_line)
        .map_err(|_| CoreError::Protocol("request line is not ASCII".to_string()))?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method.is_empty() || target.is_empty() || version.is_empty() || parts.next().is_some() {
        return Err(CoreError::Protocol(
            "request line must contain exactly method, target and version".to_string(),
        ));
    }
    if !method.bytes().all(is_token_byte) {
        return Err(CoreError::Protocol(
            "invalid request method token".to_string(),
        ));
    }
    if method.bytes().any(|byte| byte.is_ascii_lowercase()) {
        return Err(CoreError::Protocol(
            "lowercase methods are not accepted".to_string(),
        ));
    }
    let version = match version {
        "HTTP/1.0" => HttpVersion::Http10,
        "HTTP/1.1" => HttpVersion::Http11,
        _ => {
            return Err(CoreError::Protocol(
                "only HTTP/1.0 and HTTP/1.1 are accepted".to_string(),
            ))
        }
    };
    let (path, query) = split_target(target)
        .ok_or_else(|| CoreError::Protocol("target must be a safe origin-form path".to_string()))?;
    let mut headers = Vec::new();
    let mut host_values = Vec::new();
    let mut content_lengths = Vec::new();
    let mut transfer_encodings = Vec::new();
    let mut connection_tokens = BTreeSet::new();
    let mut upgrade_values = Vec::new();
    let mut websocket_key = None;
    let mut websocket_version = None;
    let mut origin = None;
    let mut subprotocol_values = Vec::new();
    let mut websocket_extensions = None;
    for line in lines {
        if headers.len() >= limits.max_header_count {
            return Err(CoreError::Limit("too many HTTP headers".to_string()));
        }
        if line.is_empty()
            || line
                .first()
                .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            return Err(CoreError::Protocol(
                "obs-fold and empty header lines are not accepted".to_string(),
            ));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| CoreError::Protocol("header line has no colon".to_string()))?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().copied().all(is_token_byte) {
            return Err(CoreError::Protocol("invalid HTTP header name".to_string()));
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| CoreError::Protocol("header name is not ASCII".to_string()))?
            .to_ascii_lowercase();
        let raw_value = &line[colon + 1..];
        if raw_value
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
        {
            return Err(CoreError::Protocol(
                "control character in HTTP header value".to_string(),
            ));
        }
        let value = std::str::from_utf8(raw_value)
            .map_err(|_| {
                CoreError::Protocol("non-ASCII HTTP header value is not accepted".to_string())
            })?
            .trim_matches([' ', '\t'])
            .to_string();
        match name.as_str() {
            "host" => host_values.push(value.clone()),
            "content-length" => content_lengths.push(value.clone()),
            "transfer-encoding" => transfer_encodings.push(value.clone()),
            "connection" => connection_tokens.extend(header_tokens(&value)),
            "upgrade" => upgrade_values.push(value.clone()),
            "sec-websocket-key" => {
                if websocket_key.replace(value.clone()).is_some() {
                    return Err(CoreError::Protocol(
                        "duplicate Sec-WebSocket-Key is not accepted".to_string(),
                    ));
                }
            }
            "sec-websocket-version" => {
                if websocket_version.replace(value.clone()).is_some() {
                    return Err(CoreError::Protocol(
                        "duplicate Sec-WebSocket-Version is not accepted".to_string(),
                    ));
                }
            }
            "origin" => {
                if origin.replace(value.clone()).is_some() {
                    return Err(CoreError::Protocol(
                        "duplicate Origin is not accepted".to_string(),
                    ));
                }
            }
            "sec-websocket-protocol" => subprotocol_values.push(value.clone()),
            "sec-websocket-extensions" => {
                if websocket_extensions.replace(value.clone()).is_some() {
                    return Err(CoreError::Protocol(
                        "duplicate Sec-WebSocket-Extensions is not accepted".to_string(),
                    ));
                }
            }
            "te" | "trailer" | "expect" | "proxy-connection" => {
                return Err(CoreError::Protocol(format!(
                    "{name} is not accepted on the H1 data plane"
                )));
            }
            _ => {}
        }
        headers.push(HeaderField { name, value });
    }
    if host_values.len() != 1 {
        return Err(CoreError::Protocol(
            "exactly one Host header is required".to_string(),
        ));
    }
    let host = normalize_authority(&host_values[0])?;
    if content_lengths.len() > 1 {
        return Err(CoreError::Protocol(
            "duplicate Content-Length is not accepted".to_string(),
        ));
    }
    if transfer_encodings.len() > 1 {
        return Err(CoreError::Protocol(
            "duplicate Transfer-Encoding is not accepted".to_string(),
        ));
    }
    if !transfer_encodings.is_empty() && !content_lengths.is_empty() {
        return Err(CoreError::Protocol(
            "Transfer-Encoding and Content-Length cannot be combined".to_string(),
        ));
    }
    let content_length = content_lengths
        .first()
        .map(|value| parse_content_length(value))
        .transpose()?;
    let chunked = match transfer_encodings.first() {
        Some(value) => {
            if !is_single_chunked(value) || version == HttpVersion::Http10 {
                return Err(CoreError::Protocol(
                    "only a single chunked Transfer-Encoding is accepted".to_string(),
                ));
            }
            if upgrade_values.is_empty() {
                true
            } else {
                return Err(CoreError::Protocol(
                    "upgrade requests cannot carry a request body".to_string(),
                ));
            }
        }
        None => false,
    };
    let upgrade = if upgrade_values.is_empty() {
        None
    } else {
        if upgrade_values.len() != 1 || !upgrade_values[0].eq_ignore_ascii_case("websocket") {
            return Err(CoreError::Protocol(
                "only a single websocket Upgrade is accepted".to_string(),
            ));
        }
        if !connection_tokens.contains("upgrade")
            || method != "GET"
            || version != HttpVersion::Http11
        {
            return Err(CoreError::Protocol(
                "invalid WebSocket upgrade headers".to_string(),
            ));
        }
        let key = websocket_key
            .ok_or_else(|| CoreError::Protocol("missing Sec-WebSocket-Key".to_string()))?;
        if !valid_websocket_key(&key) {
            return Err(CoreError::Protocol("invalid Sec-WebSocket-Key".to_string()));
        }
        if websocket_version.as_deref() != Some("13") {
            return Err(CoreError::Protocol(
                "only WebSocket version 13 is accepted".to_string(),
            ));
        }
        if content_length.is_some() || chunked {
            return Err(CoreError::Protocol(
                "WebSocket handshake cannot carry a request body".to_string(),
            ));
        }
        if subprotocol_values.len() > 1 {
            return Err(CoreError::Protocol(
                "duplicate Sec-WebSocket-Protocol is not accepted".to_string(),
            ));
        }
        let mut subprotocols = Vec::new();
        if let Some(value) = subprotocol_values.first() {
            if value.len() > 1024 {
                return Err(CoreError::Limit(
                    "Sec-WebSocket-Protocol exceeds the configured budget".to_string(),
                ));
            }
            for token in value.split(',') {
                let token = token.trim();
                if token.is_empty() || token.len() > 256 || !token.bytes().all(is_token_byte) {
                    return Err(CoreError::Protocol(
                        "invalid Sec-WebSocket-Protocol".to_string(),
                    ));
                }
                if subprotocols.iter().any(|existing| existing == token) {
                    return Err(CoreError::Protocol(
                        "duplicate Sec-WebSocket-Protocol token".to_string(),
                    ));
                }
                subprotocols.push(token.to_string());
            }
        }
        if subprotocols.len() > 32 {
            return Err(CoreError::Limit(
                "too many Sec-WebSocket-Protocol values".to_string(),
            ));
        }
        if websocket_extensions
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 1024)
        {
            return Err(CoreError::Protocol(
                "invalid Sec-WebSocket-Extensions".to_string(),
            ));
        }
        Some(UpgradeRequest {
            websocket_key: key,
            version: "13".to_string(),
            origin,
            subprotocols,
            extensions: websocket_extensions,
        })
    };
    if connection_tokens.contains("upgrade") && upgrade.is_none() {
        return Err(CoreError::Protocol(
            "Connection: upgrade without a valid Upgrade is not accepted".to_string(),
        ));
    }
    Ok(RequestHead {
        method: method.to_string(),
        target: target.to_string(),
        path,
        query,
        version,
        headers,
        host,
        content_length,
        chunked,
        connection_tokens,
        upgrade,
    })
}

pub fn parse_response_head(block: &[u8], limits: &LimitsConfig) -> Result<ResponseHead> {
    let mut lines = split_crlf(block)?;
    let status_line = lines
        .next()
        .ok_or_else(|| CoreError::Upstream("empty response head".to_string()))?;
    let status_line = std::str::from_utf8(status_line)
        .map_err(|_| CoreError::Upstream("response status line is not ASCII".to_string()))?;
    let (version, rest) = if let Some(rest) = status_line.strip_prefix("HTTP/1.1 ") {
        (HttpVersion::Http11, rest)
    } else if let Some(rest) = status_line.strip_prefix("HTTP/1.0 ") {
        (HttpVersion::Http10, rest)
    } else {
        return Err(CoreError::Upstream(
            "invalid upstream response version".to_string(),
        ));
    };
    if rest.len() < 3
        || !rest.as_bytes()[..3]
            .iter()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(CoreError::Upstream(
            "invalid upstream status code".to_string(),
        ));
    }
    let status = rest[..3]
        .parse::<u16>()
        .map_err(|_| CoreError::Upstream("invalid upstream status code".to_string()))?;
    if !(100..=599).contains(&status) {
        return Err(CoreError::Upstream(
            "upstream status code out of range".to_string(),
        ));
    }
    if rest.len() > 3 && !rest.as_bytes()[3].is_ascii_whitespace() {
        return Err(CoreError::Upstream(
            "invalid upstream status line".to_string(),
        ));
    }
    let reason = rest.get(4..).unwrap_or("").to_string();
    let mut headers = Vec::new();
    let mut content_lengths = Vec::new();
    let mut transfer_encodings = Vec::new();
    let mut connection_close = false;
    for line in lines {
        if headers.len() >= limits.max_header_count {
            return Err(CoreError::Upstream("too many upstream headers".to_string()));
        }
        if line.is_empty()
            || line
                .first()
                .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            return Err(CoreError::Upstream(
                "invalid upstream header folding".to_string(),
            ));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| CoreError::Upstream("upstream header has no colon".to_string()))?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().copied().all(is_token_byte) {
            return Err(CoreError::Upstream(
                "invalid upstream header name".to_string(),
            ));
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| CoreError::Upstream("non-ASCII upstream header name".to_string()))?
            .to_ascii_lowercase();
        let raw_value = &line[colon + 1..];
        if raw_value
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
        {
            return Err(CoreError::Upstream(
                "control character in upstream header".to_string(),
            ));
        }
        let value = std::str::from_utf8(raw_value)
            .map_err(|_| CoreError::Upstream("non-ASCII upstream header value".to_string()))?
            .trim_matches([' ', '\t'])
            .to_string();
        match name.as_str() {
            "content-length" => content_lengths.push(value.clone()),
            "transfer-encoding" => transfer_encodings.push(value.clone()),
            "connection" => {
                let tokens = header_tokens(&value);
                if tokens.contains("close") || tokens.contains("upgrade") {
                    connection_close = true;
                }
            }
            _ => {}
        }
        headers.push(HeaderField { name, value });
    }
    if content_lengths.len() > 1 || (!content_lengths.is_empty() && !transfer_encodings.is_empty())
    {
        return Err(CoreError::Upstream(
            "ambiguous upstream response framing".to_string(),
        ));
    }
    let content_length = content_lengths
        .first()
        .map(|value| parse_content_length(value))
        .transpose()?;
    let chunked = match transfer_encodings.first() {
        Some(value) => {
            if !is_single_chunked(value) {
                return Err(CoreError::Upstream(
                    "invalid upstream Transfer-Encoding".to_string(),
                ));
            }
            true
        }
        None => false,
    };
    Ok(ResponseHead {
        version,
        status,
        reason,
        headers,
        content_length,
        chunked,
        connection_close,
    })
}

fn split_crlf(block: &[u8]) -> Result<impl Iterator<Item = &[u8]>> {
    if !block.ends_with(b"\r\n\r\n") {
        return Err(CoreError::Protocol(
            "head does not end with an empty CRLF line".to_string(),
        ));
    }
    if block
        .windows(1)
        .enumerate()
        .any(|(index, byte)| byte == b"\n" && (index == 0 || block[index - 1] != b'\r'))
    {
        return Err(CoreError::Protocol("bare LF in HTTP head".to_string()));
    }
    let without_end = &block[..block.len() - 4];
    Ok(without_end
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line)))
}

pub fn parse_content_length(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CoreError::Protocol("invalid Content-Length".to_string()));
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err(CoreError::Protocol(
            "leading-zero Content-Length is not accepted".to_string(),
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| CoreError::Protocol("Content-Length is too large".to_string()))
}

pub fn normalize_authority(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 255
        || value.contains([' ', '\t', ',', '@', '/', '\\'])
        || value.ends_with('.')
    {
        return Err(CoreError::Protocol("invalid Host authority".to_string()));
    }
    let host = if let Some(rest) = value.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(CoreError::Protocol(
                "unterminated bracketed IPv6 host".to_string(),
            ));
        };
        let address = &rest[..end];
        address
            .parse::<Ipv6Addr>()
            .map_err(|_| CoreError::Protocol("invalid IPv6 Host".to_string()))?;
        let suffix = &rest[end + 1..];
        if !suffix.is_empty() {
            let port = suffix
                .strip_prefix(':')
                .ok_or_else(|| CoreError::Protocol("invalid bracketed Host suffix".to_string()))?;
            validate_port(port)?;
        }
        address.to_ascii_lowercase()
    } else if value.matches(':').count() > 1 {
        return Err(CoreError::Protocol(
            "unbracketed IPv6 Host is not accepted".to_string(),
        ));
    } else {
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (value, None),
        };
        if let Some(port) = port {
            validate_port(port)?;
        }
        if host.parse::<Ipv4Addr>().is_ok() {
            host.to_ascii_lowercase()
        } else {
            validate_hostname(host)?;
            host.to_ascii_lowercase()
        }
    };
    if host.is_empty() {
        return Err(CoreError::Protocol("Host is empty".to_string()));
    }
    Ok(host)
}

fn validate_port(value: &str) -> Result<()> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CoreError::Protocol("invalid Host port".to_string()));
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| CoreError::Protocol("invalid Host port".to_string()))?;
    if port == 0 {
        return Err(CoreError::Protocol("Host port cannot be zero".to_string()));
    }
    Ok(())
}

fn validate_hostname(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 253 || value.starts_with('.') || value.ends_with('.') {
        return Err(CoreError::Protocol("invalid Host name".to_string()));
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(CoreError::Protocol("invalid Host label".to_string()));
        }
    }
    Ok(())
}

pub async fn read_request_body<R>(
    reader: &mut BufReader<R>,
    head: &RequestHead,
    limit: usize,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    if head.upgrade.is_some() {
        return Ok(Vec::new());
    }
    if head.chunked {
        return read_chunked(reader, limit).await;
    }
    match head.content_length {
        Some(length) => read_exact_body(reader, length, limit).await,
        None => Ok(Vec::new()),
    }
}

pub async fn read_response_body<R>(
    reader: &mut BufReader<R>,
    head: &ResponseHead,
    request_method: &str,
    limit: usize,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    if head.status == 204 || head.status == 304 || (100..200).contains(&head.status) {
        return Ok(Vec::new());
    }
    if request_method.eq_ignore_ascii_case("HEAD") {
        return Ok(Vec::new());
    }
    if head.chunked {
        return read_chunked(reader, limit).await;
    }
    match head.content_length {
        Some(length) => read_exact_body(reader, length, limit).await,
        None => read_until_eof(reader, limit).await,
    }
}

async fn read_exact_body<R>(reader: &mut R, length: u64, limit: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let length =
        usize::try_from(length).map_err(|_| CoreError::Limit("body is too large".to_string()))?;
    if length > limit {
        return Err(CoreError::Limit(
            "body exceeds configured limit".to_string(),
        ));
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

async fn read_chunked<R>(reader: &mut BufReader<R>, limit: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut body = Vec::new();
    loop {
        let Some(line) = read_line(reader, 1024).await? else {
            return Err(CoreError::Protocol(
                "chunked body ended before final chunk".to_string(),
            ));
        };
        let size_text = line[..line.len().saturating_sub(2)]
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or(b"");
        if size_text.is_empty() || size_text.len() > 16 {
            return Err(CoreError::Protocol("invalid chunk size".to_string()));
        }
        let size_text = std::str::from_utf8(size_text)
            .map_err(|_| CoreError::Protocol("chunk size is not ASCII".to_string()))?;
        let size = u64::from_str_radix(size_text, 16)
            .map_err(|_| CoreError::Protocol("invalid chunk size".to_string()))?;
        if size == 0 {
            let Some(trailer_end) = read_line(reader, 8192).await? else {
                return Err(CoreError::Protocol("truncated chunked body".to_string()));
            };
            if trailer_end != b"\r\n" {
                return Err(CoreError::Protocol(
                    "HTTP/1.1 trailers are not accepted".to_string(),
                ));
            }
            return Ok(body);
        }
        let size = usize::try_from(size)
            .map_err(|_| CoreError::Limit("chunk is too large".to_string()))?;
        if size > limit.saturating_sub(body.len()) {
            return Err(CoreError::Limit(
                "chunked body exceeds configured limit".to_string(),
            ));
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader.read_exact(&mut body[start..]).await?;
        let mut crlf = [0_u8; 2];
        reader.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(CoreError::Protocol(
                "chunk data is not terminated by CRLF".to_string(),
            ));
        }
    }
}

fn is_single_chunked(value: &str) -> bool {
    let mut tokens = value.split(',').map(str::trim);
    matches!(
        (tokens.next(), tokens.next()),
        (Some(token), None) if token.eq_ignore_ascii_case("chunked")
    )
}

async fn read_until_eof<R>(reader: &mut R, limit: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut body = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(body);
        }
        if body.len().saturating_add(read) > limit {
            return Err(CoreError::Limit(
                "response body exceeds configured limit".to_string(),
            ));
        }
        body.extend_from_slice(&buffer[..read]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> LimitsConfig {
        LimitsConfig::default()
    }

    #[test]
    fn rejects_cl_te_and_duplicate_host() {
        let cl_te = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(parse_request_head(cl_te, &limits()).is_err());
        let duplicate_host = b"GET / HTTP/1.1\r\nHost: localhost\r\nHost: localhost\r\n\r\n";
        assert!(parse_request_head(duplicate_host, &limits()).is_err());
        let duplicate_chunked =
            b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, chunked\r\n\r\n";
        assert!(parse_request_head(duplicate_chunked, &limits()).is_err());
        let duplicate_response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n";
        assert!(parse_response_head(duplicate_response, &limits()).is_err());
    }

    #[test]
    fn rejects_bare_lf_obs_fold_and_bad_cl() {
        assert!(parse_request_head(b"GET / HTTP/1.1\r\nHost: localhost\n\r\n", &limits()).is_err());
        assert!(parse_request_head(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n bad: value\r\n\r\n",
            &limits()
        )
        .is_err());
        assert!(parse_request_head(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: +1\r\n\r\n",
            &limits()
        )
        .is_err());
        assert!(parse_request_head(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 01\r\n\r\n",
            &limits()
        )
        .is_err());
    }

    #[test]
    fn rejects_absolute_target_and_h2_preface() {
        assert!(parse_request_head(
            b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n",
            &limits()
        )
        .is_err());
        assert!(parse_request_head(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", &limits()).is_err());
    }

    #[test]
    fn accepts_strict_host_and_target_forms() {
        let request = parse_request_head(
            b"GET /health?q=1 HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\n\r\n",
            &limits(),
        )
        .unwrap();
        assert_eq!(request.host, "localhost");
        assert_eq!(request.path, "/health");
        assert_eq!(request.query.as_deref(), Some("q=1"));
        assert!(request.connection_tokens.contains("keep-alive"));
    }

    #[test]
    fn parses_websocket_handshake_strictly() {
        let request = parse_request_head(
            b"GET /socket HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: https://localhost\r\n\r\n",
            &limits(),
        )
        .unwrap();
        let upgrade = request.upgrade.unwrap();
        assert_eq!(upgrade.version, "13");
        assert_eq!(upgrade.origin.as_deref(), Some("https://localhost"));
    }

    #[tokio::test]
    async fn chunked_body_is_bounded_and_decoded() {
        let mut reader = BufReader::new(&b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"[..]);
        assert_eq!(read_chunked(&mut reader, 32).await.unwrap(), b"Wikipedia");
    }

    #[tokio::test]
    async fn chunked_trailers_are_rejected_instead_of_dropped() {
        let mut reader = BufReader::new(&b"1\r\na\r\n0\r\nX-Checksum: 1\r\n\r\n"[..]);
        assert!(read_chunked(&mut reader, 32).await.is_err());
    }

    #[tokio::test]
    async fn header_line_limit_is_not_widened_to_the_whole_head_budget() {
        let mut limits = limits();
        limits.max_header_line_bytes = 128;
        limits.max_head_bytes = 4096;
        let mut request = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: ".to_vec();
        request.extend_from_slice(&[b'a'; 200]);
        request.extend_from_slice(b"\r\n\r\n");
        let mut reader = BufReader::new(request.as_slice());
        assert!(read_head_block(&mut reader, &limits).await.is_err());
    }

    #[tokio::test]
    async fn head_response_body_is_not_read_from_upstream() {
        let head = ResponseHead {
            version: HttpVersion::Http11,
            status: 200,
            reason: "OK".to_string(),
            headers: Vec::new(),
            content_length: Some(10),
            chunked: false,
            connection_close: false,
        };
        let mut reader = BufReader::new(&b"short"[..]);
        assert_eq!(
            read_response_body(&mut reader, &head, "HEAD", 1024)
                .await
                .unwrap(),
            Vec::<u8>::new()
        );
    }
}
