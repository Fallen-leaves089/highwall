use std::collections::BTreeSet;

use crate::{
    config::LimitsConfig,
    error::{CoreError, Result},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

impl HttpVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct UpgradeRequest {
    pub websocket_key: String,
    pub version: String,
    pub origin: Option<String>,
    pub subprotocols: Vec<String>,
    pub extensions: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub path: String,
    pub query: Option<String>,
    pub version: HttpVersion,
    pub headers: Vec<HeaderField>,
    pub host: String,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub connection_tokens: BTreeSet<String>,
    pub upgrade: Option<UpgradeRequest>,
}

#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub version: HttpVersion,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<HeaderField>,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub connection_close: bool,
}

impl RequestHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case(name))
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    pub fn is_websocket(&self) -> bool {
        self.upgrade.is_some()
    }

    pub fn is_grpc(&self) -> bool {
        self.content_type().is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/grpc"))
        })
    }
}

impl ResponseHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }
}

pub fn header_tokens(value: &str) -> BTreeSet<String> {
    value
        .split(',')
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

pub fn fields_from_http_headers(
    headers: &http::HeaderMap,
    limits: &LimitsConfig,
) -> Result<Vec<HeaderField>> {
    let mut fields = Vec::with_capacity(headers.len().min(limits.max_header_count));
    let mut total = 0_usize;
    for (name, value) in headers {
        if name.as_str().starts_with(':') {
            continue;
        }
        if fields.len() >= limits.max_header_count {
            return Err(CoreError::Limit(
                "too many HTTP/2 or HTTP/3 headers".to_string(),
            ));
        }
        let value = value.to_str().map_err(|_| {
            CoreError::Protocol(
                "non-ASCII HTTP/2 or HTTP/3 header value is not accepted".to_string(),
            )
        })?;
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(CoreError::Protocol(
                "control character in HTTP/2 or HTTP/3 header value".to_string(),
            ));
        }
        total = total.saturating_add(name.as_str().len() + value.len() + 4);
        if name.as_str().len() + value.len() > limits.max_header_line_bytes
            || total > limits.max_head_bytes
        {
            return Err(CoreError::Limit(
                "HTTP/2 or HTTP/3 header list exceeds the configured limit".to_string(),
            ));
        }
        fields.push(HeaderField {
            name: name.as_str().to_string(),
            value: value.to_string(),
        });
    }
    Ok(fields)
}

pub fn fields_to_http_headers(fields: &[HeaderField]) -> Result<http::HeaderMap> {
    let mut headers = http::HeaderMap::new();
    for field in fields {
        let name = http::HeaderName::from_bytes(field.name.as_bytes()).map_err(|_| {
            CoreError::Protocol(format!("invalid response header name: {}", field.name))
        })?;
        let value = http::HeaderValue::from_str(&field.value).map_err(|_| {
            CoreError::Protocol(format!("invalid response header value for {}", field.name))
        })?;
        headers.append(name, value);
    }
    Ok(headers)
}

pub fn split_target(target: &str) -> Option<(String, Option<String>)> {
    if !target.starts_with('/') || target.starts_with("//") || target.contains('#') {
        return None;
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query.to_string())),
        None => (target, None),
    };
    if path.is_empty() || path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f) {
        return None;
    }
    if query
        .as_ref()
        .is_some_and(|value| value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f))
    {
        return None;
    }
    Some((path.to_string(), query))
}

pub fn request_head_from_http_parts(
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    version: HttpVersion,
    secure_transport: bool,
    limits: &LimitsConfig,
) -> Result<RequestHead> {
    let method_text = method.as_str();
    if method_text.is_empty()
        || !method_text.bytes().all(crate::config::is_token_byte)
        || method_text.bytes().any(|byte| byte.is_ascii_lowercase())
    {
        return Err(CoreError::Protocol(
            "invalid HTTP/2 or HTTP/3 method".to_string(),
        ));
    }
    if matches!(method_text, "CONNECT" | "TRACE") {
        return Err(CoreError::Protocol(
            "CONNECT and TRACE are not accepted on checked routes".to_string(),
        ));
    }
    let expected_scheme = if secure_transport { "https" } else { "http" };
    if uri.scheme_str() != Some(expected_scheme) {
        return Err(CoreError::Protocol(
            "HTTP/2 or HTTP/3 request scheme does not match the transport".to_string(),
        ));
    }
    if uri.path().is_empty() || !uri.path().starts_with('/') || uri.path().starts_with("//") {
        return Err(CoreError::Protocol(
            "HTTP/2 or HTTP/3 request must use an origin-form path".to_string(),
        ));
    }
    let path_and_query = uri
        .path_and_query()
        .ok_or_else(|| CoreError::Protocol("request path is missing".to_string()))?;
    let target = path_and_query.as_str();
    let (path, query) = split_target(target).ok_or_else(|| {
        CoreError::Protocol("request target is not a safe origin-form path".to_string())
    })?;
    let authority = uri
        .authority()
        .ok_or_else(|| CoreError::Protocol("HTTP/2 or HTTP/3 authority is required".to_string()))?;
    let host = crate::h1::normalize_authority(authority.as_str())?;
    let mut host_headers = headers.get_all(http::header::HOST).iter();
    if let Some(host_header) = host_headers.next() {
        if host_headers.next().is_some() {
            return Err(CoreError::Protocol(
                "duplicate Host header is not accepted".to_string(),
            ));
        }
        let value = host_header
            .to_str()
            .map_err(|_| CoreError::Protocol("non-ASCII Host header".to_string()))?;
        if crate::h1::normalize_authority(value)? != host {
            return Err(CoreError::Protocol(
                "Host header does not match the HTTP/2 or HTTP/3 authority".to_string(),
            ));
        }
    }
    let mut content_lengths = Vec::new();
    for value in headers.get_all(http::header::CONTENT_LENGTH).iter() {
        let value = value
            .to_str()
            .map_err(|_| CoreError::Protocol("non-ASCII Content-Length".to_string()))?;
        content_lengths.push(value.to_string());
    }
    if content_lengths.len() > 1 {
        return Err(CoreError::Protocol(
            "duplicate Content-Length is not accepted".to_string(),
        ));
    }
    let content_length = content_lengths
        .first()
        .map(|value| crate::h1::parse_content_length(value))
        .transpose()?;
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "trailer",
        "expect",
    ] {
        if headers.contains_key(name) {
            return Err(CoreError::Protocol(format!(
                "connection-specific header {name} is not accepted"
            )));
        }
    }
    if let Some(te) = headers.get(http::header::TE) {
        let value = te
            .to_str()
            .map_err(|_| CoreError::Protocol("non-ASCII TE header".to_string()))?;
        if !value.trim().eq_ignore_ascii_case("trailers") {
            return Err(CoreError::Protocol(
                "TE is only accepted with the trailers value".to_string(),
            ));
        }
    }
    for name in [
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-extensions",
    ] {
        if headers.contains_key(name) {
            return Err(CoreError::Protocol(
                "WebSocket upgrade fields are not accepted on HTTP/2 or HTTP/3".to_string(),
            ));
        }
    }
    let fields = fields_from_http_headers(headers, limits)?;
    Ok(RequestHead {
        method: method_text.to_string(),
        target: target.to_string(),
        path,
        query,
        version,
        headers: fields,
        host,
        content_length,
        chunked: false,
        connection_tokens: BTreeSet::new(),
        upgrade: None,
    })
}

pub fn validate_trailer_fields(fields: &[HeaderField]) -> Result<()> {
    for field in fields {
        if field.name.starts_with(':')
            || matches!(
                field.name.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
                    | "upgrade"
                    | "te"
                    | "trailer"
                    | "content-length"
                    | "host"
                    | "expect"
            )
        {
            return Err(CoreError::Protocol(format!(
                "trailer field {} is not accepted",
                field.name
            )));
        }
    }
    Ok(())
}

pub fn response_fields_for_h2_h3(
    fields: &[HeaderField],
    content_length: u64,
    status: u16,
) -> Result<Vec<HeaderField>> {
    let mut connection_nominated = BTreeSet::new();
    for field in fields {
        if field.name.eq_ignore_ascii_case("connection")
            || field.name.eq_ignore_ascii_case("proxy-connection")
        {
            connection_nominated.extend(header_tokens(&field.value));
        }
    }
    let mut output = Vec::with_capacity(fields.len().saturating_add(1));
    for field in fields {
        let name = field.name.to_ascii_lowercase();
        if name.starts_with(':')
            || connection_nominated.contains(&name)
            || matches!(
                name.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
                    | "upgrade"
                    | "te"
                    | "trailer"
                    | "content-length"
            )
        {
            continue;
        }
        http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            CoreError::Protocol("invalid upstream response header name".to_string())
        })?;
        http::HeaderValue::from_str(&field.value).map_err(|_| {
            CoreError::Protocol("invalid upstream response header value".to_string())
        })?;
        output.push(HeaderField {
            name,
            value: field.value.clone(),
        });
    }
    if status != 204 && status != 304 && !(100..200).contains(&status) {
        output.push(HeaderField {
            name: "content-length".to_string(),
            value: content_length.to_string(),
        });
    }
    Ok(output)
}
