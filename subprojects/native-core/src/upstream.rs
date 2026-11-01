use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

use crate::{
    config::{AppConfig, RouteConfig, UpstreamConfig},
    error::{CoreError, Result},
    h1::{read_response_head, BodyKind},
    http::{
        fields_from_http_headers, fields_to_http_headers, HeaderField, RequestHead, ResponseHead,
    },
};

#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    pub host: String,
    pub port: u16,
    pub set_forwarded_for: bool,
}

#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub head: ResponseHead,
    pub body: Vec<u8>,
    pub trailers: Vec<HeaderField>,
}

impl UpstreamTarget {
    pub fn from_config(config: &AppConfig, route: &RouteConfig) -> Self {
        let source: &UpstreamConfig = route.upstream.as_ref().unwrap_or(&config.upstream);
        Self {
            host: source.host.clone(),
            port: source.port,
            set_forwarded_for: source.set_forwarded_for,
        }
    }

    pub async fn connect(&self, config: &AppConfig) -> Result<TcpStream> {
        let address = format!("{}:{}", self.host, self.port);
        let stream = timeout(
            Duration::from_millis(config.limits.upstream_connect_timeout_ms),
            TcpStream::connect(&address),
        )
        .await
        .map_err(|_| CoreError::Upstream("upstream connect timed out".to_string()))?
        .map_err(|error| CoreError::Upstream(format!("upstream connect failed: {error}")))?;
        stream.set_nodelay(true).map_err(|error| {
            CoreError::Upstream(format!("cannot set upstream TCP_NODELAY: {error}"))
        })?;
        Ok(stream)
    }
}

pub fn build_h1_request(
    head: &RequestHead,
    body: &[u8],
    peer: SocketAddr,
    request_id: u64,
    target: &UpstreamTarget,
    protocol: &str,
) -> Vec<u8> {
    let websocket = head.upgrade.is_some();
    let mut output = Vec::with_capacity(1024 + body.len());
    output.extend_from_slice(head.method.as_bytes());
    output.push(b' ');
    output.extend_from_slice(head.target.as_bytes());
    output.extend_from_slice(b" HTTP/1.1\r\n");
    for header in &head.headers {
        if is_hop_by_hop(&header.name) && !(websocket && websocket_header(&header.name)) {
            continue;
        }
        if header.name == "content-length" || header.name == "transfer-encoding" {
            continue;
        }
        if header.name == "x-forwarded-for"
            || header.name == "x-forwarded-proto"
            || header.name == "forwarded"
            || header.name == "x-highwall-request-id"
        {
            continue;
        }
        output.extend_from_slice(header.name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(header.value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    if target.set_forwarded_for {
        output.extend_from_slice(b"X-Forwarded-For: ");
        output.extend_from_slice(peer.ip().to_string().as_bytes());
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(b"X-Forwarded-Proto: ");
        output.extend_from_slice(protocol.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(format!("X-HighWall-Request-Id: {request_id}\r\n").as_bytes());
    if websocket {
        output.extend_from_slice(b"Connection: Upgrade\r\n");
    } else {
        output.extend_from_slice(b"Connection: close\r\n");
        if head.content_length.is_some() || head.chunked || !body.is_empty() {
            output.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(body);
    output
}

pub async fn exchange_h1(
    stream: TcpStream,
    request: &[u8],
    request_method: &str,
    config: &AppConfig,
) -> Result<(BufReader<TcpStream>, crate::http::ResponseHead, Vec<u8>)> {
    let mut stream = stream;
    stream
        .write_all(request)
        .await
        .map_err(|error| CoreError::Upstream(format!("upstream write failed: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| CoreError::Upstream(format!("upstream flush failed: {error}")))?;
    let mut reader = BufReader::new(stream);
    let response = timeout(
        Duration::from_millis(config.limits.upstream_read_timeout_ms),
        read_response_head(&mut reader, &config.limits),
    )
    .await
    .map_err(|_| CoreError::Upstream("upstream response head timed out".to_string()))??;
    if response.status == 101 {
        return Ok((reader, response, Vec::new()));
    }
    let body_limit = config.limits.max_response_bytes;
    let body = timeout(
        Duration::from_millis(config.limits.upstream_read_timeout_ms),
        crate::h1::read_response_body(&mut reader, &response, request_method, body_limit),
    )
    .await
    .map_err(|_| CoreError::Upstream("upstream response body timed out".to_string()))??;
    Ok((reader, response, body))
}

pub fn body_kind(head: &crate::http::ResponseHead) -> BodyKind {
    if head.chunked {
        BodyKind::Chunked
    } else if let Some(length) = head.content_length {
        BodyKind::ContentLength(length)
    } else {
        BodyKind::UntilEof
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn exchange_h2(
    stream: TcpStream,
    head: &RequestHead,
    body: &[u8],
    request_trailers: &[HeaderField],
    peer: SocketAddr,
    request_id: u64,
    target: &UpstreamTarget,
    config: &AppConfig,
    protocol: &str,
) -> Result<UpstreamResponse> {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(256 * 1024)
        .max_frame_size(16_384)
        .max_header_list_size(config.limits.max_h2_header_list_bytes as u32)
        .max_send_buffer_size(config.limits.max_h2_send_buffer_bytes);
    let (mut client, connection) = timeout(
        Duration::from_millis(config.limits.upstream_connect_timeout_ms),
        builder.handshake(stream),
    )
    .await
    .map_err(|_| CoreError::Upstream("upstream HTTP/2 handshake timed out".to_string()))?
    .map_err(|error| CoreError::Upstream(format!("upstream HTTP/2 handshake failed: {error}")))?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let authority = format_authority(&target.host, target.port);
    let uri = http::Uri::builder()
        .scheme("http")
        .authority(authority.clone())
        .path_and_query(head.target.as_str())
        .build()
        .map_err(|error| CoreError::Upstream(format!("invalid upstream URI: {error}")))?;
    let method = http::Method::from_bytes(head.method.as_bytes())
        .map_err(|error| CoreError::Upstream(format!("invalid upstream method: {error}")))?;
    let request = http::Request::builder()
        .method(method)
        .uri(uri)
        .version(http::Version::HTTP_2)
        .body(())
        .map_err(|error| CoreError::Upstream(format!("cannot build upstream request: {error}")))?;
    let mut headers = http::HeaderMap::new();
    for header in &head.headers {
        if is_hop_by_hop(&header.name)
            || matches!(
                header.name.as_str(),
                "host" | "content-length" | "transfer-encoding" | "upgrade"
            )
            || header.name == "x-forwarded-for"
            || header.name == "x-forwarded-proto"
            || header.name == "forwarded"
            || header.name == "x-highwall-request-id"
        {
            continue;
        }
        if header.name == "te" && !header.value.eq_ignore_ascii_case("trailers") {
            continue;
        }
        let name = http::HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| CoreError::Upstream("invalid request header name".to_string()))?;
        let value = http::HeaderValue::from_str(&header.value)
            .map_err(|_| CoreError::Upstream("invalid request header value".to_string()))?;
        headers.append(name, value);
    }
    if head.is_grpc() && !headers.contains_key("te") {
        headers.insert("te", http::HeaderValue::from_static("trailers"));
    }
    if target.set_forwarded_for {
        headers.append(
            "x-forwarded-for",
            http::HeaderValue::from_str(&peer.ip().to_string())
                .map_err(|_| CoreError::Upstream("invalid X-Forwarded-For value".to_string()))?,
        );
        headers.append(
            "x-forwarded-proto",
            http::HeaderValue::from_str(protocol)
                .map_err(|_| CoreError::Upstream("invalid X-Forwarded-Proto value".to_string()))?,
        );
    }
    headers.insert(
        "x-highwall-request-id",
        http::HeaderValue::from_str(&request_id.to_string())
            .map_err(|_| CoreError::Upstream("invalid request id header".to_string()))?,
    );
    let mut request = request;
    *request.headers_mut() = headers;
    let trailers = fields_to_http_headers(request_trailers)?;
    let end_stream = body.is_empty() && trailers.is_empty();
    let (response, mut send_stream) =
        client.send_request(request, end_stream).map_err(|error| {
            CoreError::Upstream(format!("cannot start upstream HTTP/2 request: {error}"))
        })?;
    if !body.is_empty() {
        let mut sent = 0_usize;
        while sent < body.len() {
            send_stream.reserve_capacity(body.len() - sent);
            let capacity = loop {
                let capacity = send_stream.capacity();
                if capacity > 0 {
                    break capacity;
                }
                match std::future::poll_fn(|cx| send_stream.poll_capacity(cx)).await {
                    Some(Ok(value)) if value > 0 => break value,
                    Some(Ok(_)) => continue,
                    Some(Err(error)) => {
                        return Err(CoreError::Upstream(format!(
                            "upstream HTTP/2 flow control failed: {error}"
                        )));
                    }
                    None => {
                        return Err(CoreError::Upstream(
                            "upstream HTTP/2 stream closed during body upload".to_string(),
                        ));
                    }
                }
            };
            let chunk = capacity.min(body.len() - sent);
            send_stream
                .send_data(Bytes::copy_from_slice(&body[sent..sent + chunk]), false)
                .map_err(|error| {
                    CoreError::Upstream(format!("upstream HTTP/2 send failed: {error}"))
                })?;
            sent += chunk;
        }
    }
    if !trailers.is_empty() {
        send_stream.send_trailers(trailers).map_err(|error| {
            CoreError::Upstream(format!("upstream HTTP/2 trailers failed: {error}"))
        })?;
    } else if !body.is_empty() {
        send_stream.send_data(Bytes::new(), true).map_err(|error| {
            CoreError::Upstream(format!("upstream HTTP/2 close failed: {error}"))
        })?;
    }

    let response = timeout(
        Duration::from_millis(config.limits.upstream_read_timeout_ms),
        response,
    )
    .await
    .map_err(|_| CoreError::Upstream("upstream HTTP/2 response timed out".to_string()))?
    .map_err(|error| CoreError::Upstream(format!("upstream HTTP/2 response failed: {error}")))?;
    let status = response.status().as_u16();
    let response_headers = fields_from_http_headers(response.headers(), &config.limits)?;
    let mut response_body = Vec::new();
    let mut response_stream = response.into_body();
    let body_limit = config.limits.max_response_bytes;
    loop {
        let chunk = timeout(
            Duration::from_millis(config.limits.upstream_read_timeout_ms),
            response_stream.data(),
        )
        .await
        .map_err(|_| CoreError::Upstream("upstream HTTP/2 body timed out".to_string()))?;
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = chunk.map_err(|error| {
            CoreError::Upstream(format!("upstream HTTP/2 body failed: {error}"))
        })?;
        if response_body.len().saturating_add(chunk.len()) > body_limit {
            return Err(CoreError::Limit(
                "upstream HTTP/2 body exceeds the configured limit".to_string(),
            ));
        }
        response_body.extend_from_slice(&chunk);
    }
    let response_trailers = match timeout(
        Duration::from_millis(config.limits.upstream_read_timeout_ms),
        response_stream.trailers(),
    )
    .await
    .map_err(|_| CoreError::Upstream("upstream HTTP/2 trailers timed out".to_string()))?
    {
        Ok(Some(value)) => fields_from_http_headers(&value, &config.limits)?,
        Ok(None) => Vec::new(),
        Err(error) => {
            return Err(CoreError::Upstream(format!(
                "upstream HTTP/2 trailers failed: {error}"
            )));
        }
    };
    driver.abort();
    let content_length = response_headers
        .iter()
        .find(|header| header.name == "content-length")
        .map(|header| crate::h1::parse_content_length(&header.value))
        .transpose()?;
    if status == 204 || status == 304 {
        if !response_body.is_empty() {
            return Err(CoreError::Upstream(
                "upstream HTTP/2 response with no-body status contained data".to_string(),
            ));
        }
    } else if head.method != "HEAD" {
        if let Some(length) = content_length {
            if length != response_body.len() as u64 {
                return Err(CoreError::Upstream(
                    "upstream HTTP/2 Content-Length does not match the body".to_string(),
                ));
            }
        }
    }
    Ok(UpstreamResponse {
        head: ResponseHead {
            version: crate::http::HttpVersion::Http2,
            status,
            reason: http::StatusCode::from_u16(status)
                .ok()
                .and_then(|value| value.canonical_reason())
                .unwrap_or("Upstream")
                .to_string(),
            headers: response_headers,
            content_length,
            chunked: false,
            connection_close: false,
        },
        body: response_body,
        trailers: response_trailers,
    })
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn websocket_header(name: &str) -> bool {
    matches!(
        name,
        "upgrade"
            | "connection"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-protocol"
            | "sec-websocket-extensions"
    )
}

pub fn request_ip(peer: SocketAddr) -> IpAddr {
    peer.ip()
}

pub fn websocket_accept_value(key: &str) -> String {
    use base64::Engine;
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

pub async fn tunnel_streams<C, U>(client: C, upstream: U) -> Result<(u64, u64)>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let (client_to_upstream, upstream_to_client) = tokio::join!(
        copy_limited(client_read, upstream_write, 64 * 1024 * 1024),
        copy_limited(upstream_read, client_write, 64 * 1024 * 1024)
    );
    let a = client_to_upstream
        .map_err(|error| CoreError::Upstream(format!("tunnel failure: {error}")))?;
    let b = upstream_to_client
        .map_err(|error| CoreError::Upstream(format!("tunnel failure: {error}")))?;
    Ok((a, b))
}

async fn copy_limited<R, W>(mut reader: R, mut writer: W, limit: u64) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        total = total.saturating_add(read as u64);
        if total > limit {
            return Err(std::io::Error::other("tunnel byte limit exceeded"));
        }
        writer.write_all(&buffer[..read]).await?;
    }
}
