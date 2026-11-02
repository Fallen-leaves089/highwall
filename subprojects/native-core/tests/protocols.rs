use std::{
    io::Write,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use highwall_native_core::{
    config::{AppConfig, QuicConfig, RouteConfig, UpstreamConfig},
    h1_server, h2_server, h3_server,
    state::AppState,
    tls::TlsConnectionInfo,
};
use http::{Request, StatusCode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    time::{timeout, Instant},
};

const HIGH_ENTROPY_SECRET: &str =
    "api_key=5a13c8817e37eca512cb807936efa41dca837831eea71cd5827b30e9a61fd48d";

#[tokio::test]
async fn h2_request_reaches_gateway_and_upstream() {
    let upstream = spawn_h1_upstream().await;
    let state = test_state(upstream).await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40000".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, send_stream) = client.send_request(request, true).unwrap();
    drop(send_stream);
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let mut received = Vec::new();
    loop {
        match timeout(Duration::from_secs(5), body.data()).await.unwrap() {
            Some(Ok(chunk)) => received.extend_from_slice(&chunk),
            Some(Err(error)) => panic!("HTTP/2 response body failed: {error}"),
            None => break,
        }
    }
    assert_eq!(received, b"ok");

    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h1_head_response_without_body_is_forwarded_as_success() {
    for (path, content_length) in [
        ("/ok", 2048),
        ("/status/200", 6),
        ("/large", 2 * 1024 * 1024),
        ("/echo", 0),
    ] {
        let upstream_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let (upstream, upstream_hits) = spawn_raw_h1_upstream(upstream_response).await;
        let state = test_state_with(upstream, |config| {
            config.routes[0].path_prefix = "/".to_string();
            config.routes[0].methods.push("HEAD".to_string());
        })
        .await;
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(h1_server::serve_connection(
            server_io,
            "127.0.0.1:40001".parse().unwrap(),
            tls_info("http/1.1"),
            state,
        ));
        client_io
            .write_all(
                format!("HEAD {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), client_io.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "{path}: {response}");
        assert!(
            response.contains(&format!("Content-Length: {content_length}")),
            "{path}: {response}"
        );
        let (_, body) = response
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("{path}: response head was not terminated"));
        assert!(body.is_empty(), "{path}: HEAD response carried a body");
        assert_eq!(upstream_hits.load(Ordering::SeqCst), 1, "{path}");
        server.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn h2_idle_connection_is_closed_within_the_configured_budget() {
    let upstream = spawn_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.limits.h2_idle_timeout_ms = 200;
        config.bans.enabled = false;
    })
    .await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40007".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (_client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let started = Instant::now();
    timeout(Duration::from_secs(2), server)
        .await
        .expect("HTTP/2 idle connection must be closed")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    let _ = shutdown_tx.send(true);
    driver.abort();
}

#[tokio::test]
async fn h2_incomplete_preface_is_bounded_by_the_header_timeout() {
    let upstream = spawn_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.limits.header_timeout_ms = 200;
        config.bans.enabled = false;
    })
    .await;
    let (_client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40008".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));
    let result = timeout(Duration::from_secs(2), server)
        .await
        .expect("HTTP/2 preface must time out")
        .unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn h2_response_dlp_blocks_private_key_material() {
    let (upstream, upstream_hits) =
        spawn_h1_upstream_with_body(b"-----BEGIN PRIVATE KEY-----\nAAAA\n").await;
    let state = test_state(upstream).await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40006".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, send_stream) = client.send_request(request, true).unwrap();
    drop(send_stream);
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let mut body = Vec::new();
    let mut response_body = response.into_body();
    while let Some(Ok(chunk)) = timeout(Duration::from_secs(5), response_body.data())
        .await
        .unwrap()
    {
        body.extend_from_slice(&chunk);
    }
    assert!(String::from_utf8_lossy(&body).contains("HW-NATIVE-DLP-002"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h2_response_header_dlp_blocks_private_key_material() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Debug: -----BEGIN PRIVATE KEY----- AAAA\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec();
    let (upstream, upstream_hits) = spawn_raw_h1_upstream(response).await;
    let state = test_state(upstream).await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40009".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, send_stream) = client.send_request(request, true).unwrap();
    drop(send_stream);
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(Ok(chunk)) = timeout(Duration::from_secs(5), body.data()).await.unwrap() {
        received.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&received);
    assert!(text.contains("HW-NATIVE-DLP-002"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h2_compressed_response_dlp_is_inspected_before_delivery() {
    let secret = b"-----BEGIN PRIVATE KEY-----\nAAAA\n";
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(secret).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        compressed.len()
    )
    .into_bytes();
    response.extend_from_slice(&compressed);
    let (upstream, upstream_hits) = spawn_raw_h1_upstream(response).await;
    let state = test_state(upstream).await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40010".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, send_stream) = client.send_request(request, true).unwrap();
    drop(send_stream);
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(Ok(chunk)) = timeout(Duration::from_secs(5), body.data()).await.unwrap() {
        received.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&received);
    assert!(text.contains("HW-NATIVE-DLP-002"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h2_request_trailer_dlp_blocks_private_key_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.routes[0].grpc = true;
        config.bans.enabled = false;
    })
    .await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40011".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        "x-secret",
        http::HeaderValue::from_static("-----BEGIN PRIVATE KEY----- AAAA"),
    );
    send_stream.send_trailers(trailers).unwrap();
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(Ok(chunk)) = timeout(Duration::from_secs(5), body.data()).await.unwrap() {
        received.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&received);
    assert!(text.contains("HW-NATIVE-DLP-002"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h2_grpc_response_body_dlp_blocks_private_key_material() {
    let secret = b"-----BEGIN PRIVATE KEY-----\nAAAA\n";
    let (upstream, upstream_hits) = spawn_h2_upstream(grpc_frame(secret), Vec::new()).await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.routes[0].grpc = true;
        config.bans.enabled = false;
    })
    .await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40012".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response, send_stream) = client.send_request(request, true).unwrap();
    drop(send_stream);
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(Ok(chunk)) = timeout(Duration::from_secs(5), body.data()).await.unwrap() {
        received.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&received);
    assert!(text.contains("HW-NATIVE-DLP-002"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h2_grpc_response_trailer_dlp_blocks_private_key_material() {
    let (upstream, upstream_hits) = spawn_h2_upstream(
        grpc_frame(b"ok"),
        vec![("x-secret", "-----BEGIN PRIVATE KEY----- AAAA")],
    )
    .await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.routes[0].grpc = true;
        config.bans.enabled = false;
    })
    .await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40013".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response, send_stream) = client.send_request(request, true).unwrap();
    drop(send_stream);
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(Ok(chunk)) = timeout(Duration::from_secs(5), body.data()).await.unwrap() {
        received.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&received);
    assert!(text.contains("HW-NATIVE-DLP-002"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h2_request_dlp_blocks_private_key_material_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state(upstream).await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40007".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream
        .send_data(
            Bytes::from_static(b"-----BEGIN PRIVATE KEY-----\nAAAA\n"),
            true,
        )
        .unwrap();
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h2_request_dlp_blocks_high_entropy_secret_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.bans.enabled = false;
    })
    .await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40008".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream
        .send_data(Bytes::from_static(HIGH_ENTROPY_SECRET.as_bytes()), true)
        .unwrap();
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h2_shutdown_is_bounded_when_a_request_body_stalls() {
    let upstream = spawn_h1_upstream().await;
    let state = test_state(upstream).await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40000".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (_response, send_stream) = client.send_request(request, false).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = tokio::time::Instant::now();
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .expect("HTTP/2 shutdown must respect its deadline")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(7));
    drop(send_stream);
    driver.abort();
}

#[tokio::test]
async fn h2_rapid_reset_closes_the_connection_without_upstream_traffic() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.limits.max_h2_reset_errors = 2;
        config.limits.max_h2_streams = 8;
        config.bans.enabled = false;
    })
    .await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40003".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut sent = 0;
    for _ in 0..64 {
        let request = Request::builder()
            .method("GET")
            .uri("https://localhost/ok")
            .header("host", "localhost")
            .body(())
            .unwrap();
        let Ok((response, mut send_stream)) = client.send_request(request, false) else {
            break;
        };
        drop(response);
        send_stream.send_reset(h2::Reason::CANCEL);
        sent += 1;
        tokio::task::yield_now().await;
    }
    assert!(sent >= 3, "the reset flood never reached the server");
    timeout(Duration::from_secs(5), server)
        .await
        .expect("HTTP/2 reset budget must close the connection")
        .unwrap()
        .unwrap();
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = shutdown_tx.send(true);
    driver.abort();
}

#[tokio::test]
async fn h2_moderate_ping_burst_does_not_block_a_valid_request() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.bans.enabled = false;
        config.agent.enabled = false;
    })
    .await;
    let (client_io, server_io) = tokio::io::duplex(128 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40014".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let (mut client, mut connection) = h2::client::handshake(client_io).await.unwrap();
    let mut pings = connection.ping_pong().unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    for _ in 0..8 {
        timeout(Duration::from_secs(2), pings.ping(h2::Ping::opaque()))
            .await
            .expect("HTTP/2 PING burst must remain responsive")
            .unwrap();
    }

    let request = Request::builder()
        .method("GET")
        .uri("https://localhost/ok")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, send_stream) = client.send_request(request, true).unwrap();
    drop(send_stream);
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = Vec::new();
    let mut response_body = response.into_body();
    while let Some(Ok(chunk)) = timeout(Duration::from_secs(5), response_body.data())
        .await
        .unwrap()
    {
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, b"ok");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .expect("HTTP/2 server must close after shutdown")
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h2_ping_rate_flood_is_closed_without_hitting_frame_total() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.bans.enabled = false;
        config.agent.enabled = false;
        config.limits.max_h2_ping_burst = 2.0;
        config.limits.max_h2_pings_per_second = 0.01;
        config.limits.max_h2_ping_frames_per_connection = 1_000;
    })
    .await;
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40016".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request.extend_from_slice(&h2_frame(0x4, 0, 0, &[]));
    for _ in 0..16 {
        request.extend_from_slice(&h2_frame(0x6, 0, 0, &[0; 8]));
    }
    client_io.write_all(&request).await.unwrap();
    client_io.flush().await.unwrap();

    timeout(Duration::from_secs(5), server)
        .await
        .expect("HTTP/2 PING flood must terminate the connection")
        .unwrap()
        .unwrap();
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn h2_ping_connection_total_is_enforced_independently() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.bans.enabled = false;
        config.agent.enabled = false;
        config.limits.max_h2_ping_burst = 100.0;
        config.limits.max_h2_pings_per_second = 1_000.0;
        config.limits.max_h2_ping_frames_per_connection = 3;
    })
    .await;
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40017".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request.extend_from_slice(&h2_frame(0x4, 0, 0, &[]));
    for _ in 0..16 {
        request.extend_from_slice(&h2_frame(0x6, 0, 0, &[0; 8]));
    }
    client_io.write_all(&request).await.unwrap();
    client_io.flush().await.unwrap();

    timeout(Duration::from_secs(5), server)
        .await
        .expect("HTTP/2 PING total budget must terminate the connection")
        .unwrap()
        .unwrap();
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn h2_invalid_settings_are_rejected_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.bans.enabled = false;
    })
    .await;
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40015".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request.extend_from_slice(&h2_frame(0x4, 0, 0, &[0, 0x02, 0, 0, 0, 2]));
    client_io.write_all(&request).await.unwrap();
    client_io.flush().await.unwrap();

    let _ = timeout(Duration::from_secs(5), server)
        .await
        .expect("invalid HTTP/2 SETTINGS must terminate the connection")
        .unwrap();
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn h2_invalid_initial_window_size_uses_flow_control_error() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.bans.enabled = false;
    })
    .await;
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40017".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request.extend_from_slice(&h2_frame(0x4, 0, 0, &[0, 4, 0x80, 0, 0, 0]));
    client_io.write_all(&request).await.unwrap();
    client_io.flush().await.unwrap();

    let (last_stream_id, error_code) = read_h2_goaway(&mut client_io).await;
    assert_eq!(last_stream_id, 0);
    assert_eq!(error_code, 3, "FLOW_CONTROL_ERROR is required");
    let _ = timeout(Duration::from_secs(5), server)
        .await
        .expect("invalid HTTP/2 INITIAL_WINDOW_SIZE must terminate the connection")
        .unwrap();
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn h2_goaway_closes_without_upstream_traffic() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.bans.enabled = false;
    })
    .await;
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40016".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request.extend_from_slice(&h2_frame(0x4, 0, 0, &[]));
    request.extend_from_slice(&h2_frame(0x7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]));
    client_io.write_all(&request).await.unwrap();
    client_io.flush().await.unwrap();

    timeout(Duration::from_secs(5), server)
        .await
        .expect("HTTP/2 GOAWAY must close the connection")
        .unwrap()
        .unwrap();
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn h2_continuation_and_header_size_floods_are_bounded() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.limits.max_h2_header_list_bytes = 1024;
        config.limits.max_h2_frame_size = 16_384;
        config.bans.enabled = false;
    })
    .await;
    let (mut client_io, server_io) = tokio::io::duplex(128 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40004".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request.extend_from_slice(&h2_frame(0x4, 0, 0, &[]));
    let header_block = [
        0x82, 0x84, 0x87, 0x41, 0x09, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
    ];
    request.extend_from_slice(&h2_frame(0x1, 0x1, 1, &header_block));
    for _ in 0..16 {
        request.extend_from_slice(&h2_frame(0x9, 0, 1, &[]));
    }
    client_io.write_all(&request).await.unwrap();
    client_io.flush().await.unwrap();

    timeout(Duration::from_secs(5), server)
        .await
        .expect("HTTP/2 CONTINUATION flood must be protocol-bounded")
        .unwrap()
        .unwrap();
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn h2_oversized_hpack_field_is_rejected_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.limits.max_h2_header_list_bytes = 1024;
        config.limits.max_h2_frame_size = 16_384;
        config.bans.enabled = false;
    })
    .await;
    let (mut client_io, server_io) = tokio::io::duplex(256 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:40005".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));

    let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request.extend_from_slice(&h2_frame(0x4, 0, 0, &[]));
    let mut header_block = vec![0x82, 0x84, 0x87, 0x41, 0x09];
    header_block.extend_from_slice(b"localhost");
    header_block.extend_from_slice(&[0x40, 0x05]);
    header_block.extend_from_slice(b"x-pad");
    header_block.extend_from_slice(&[0xff, 0x81, 0x3f]);
    header_block.extend(std::iter::repeat_n(b'A', 8 * 1024));
    request.extend_from_slice(&h2_frame(0x1, 0x5, 1, &header_block));
    client_io.write_all(&request).await.unwrap();
    client_io.flush().await.unwrap();

    timeout(Duration::from_secs(5), server)
        .await
        .expect("HTTP/2 oversized header list must be rejected")
        .unwrap()
        .unwrap();
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn h3_request_reaches_gateway_and_upstream() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let upstream = spawn_h1_upstream().await;
    let state = test_state(upstream).await;
    let (certificate, key) = test_certificate();
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate.clone()], key)
    .unwrap();
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    server_crypto.max_early_data_size = 0;
    let quic = QuicConfig::default();
    let server_config = h3_server::build_quic_server_config(&quic, &server_crypto).unwrap();
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let connection = timeout(Duration::from_secs(5), incoming)
            .await
            .unwrap()
            .unwrap();
        h3_server::serve_connection(
            connection,
            "127.0.0.1:40001".parse().unwrap(),
            tls_info("h3"),
            server_state,
            shutdown_rx,
        )
        .await
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let connection = timeout(
        Duration::from_secs(5),
        client_endpoint
            .connect(server_address, "localhost")
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut request_stream = timeout(
        Duration::from_secs(5),
        send_request.send_request(Request::get("https://localhost/ok").body(()).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    request_stream.finish().await.unwrap();
    let response = match timeout(Duration::from_secs(5), request_stream.recv_response()).await {
        Ok(Ok(response)) => response,
        other => {
            eprintln!(
                "H3 response wait failed: {other:?}; server_finished={}",
                server.is_finished()
            );
            panic!("HTTP/3 response was not received");
        }
    };
    assert_eq!(response.status(), StatusCode::OK);
    let body = timeout(Duration::from_secs(5), request_stream.recv_data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(body.chunk(), b"ok");
    assert!(request_stream.recv_data().await.unwrap().is_none());

    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_response_dlp_blocks_private_key_material() {
    let (upstream, upstream_hits) =
        spawn_h1_upstream_with_body(b"-----BEGIN PRIVATE KEY-----\nAAAA\n").await;
    let state = test_state(upstream).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;
    let mut request_stream = timeout(
        Duration::from_secs(5),
        send_request.send_request(Request::get("https://localhost/ok").body(()).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    request_stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(5), request_stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let body = timeout(Duration::from_secs(5), request_stream.recv_data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(body.chunk()).contains("HW-NATIVE-DLP-002"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_response_header_dlp_blocks_private_key_material() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Debug: -----BEGIN PRIVATE KEY----- AAAA\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec();
    let (upstream, upstream_hits) = spawn_raw_h1_upstream(response).await;
    let state = test_state(upstream).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;
    let mut request_stream = timeout(
        Duration::from_secs(5),
        send_request.send_request(Request::get("https://localhost/ok").body(()).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    request_stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(5), request_stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let body = timeout(Duration::from_secs(5), request_stream.recv_data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(body.chunk());
    assert!(text.contains("HW-NATIVE-DLP-002"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_compressed_response_dlp_is_inspected_before_delivery() {
    let secret = b"-----BEGIN PRIVATE KEY-----\nAAAA\n";
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(secret).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        compressed.len()
    )
    .into_bytes();
    response.extend_from_slice(&compressed);
    let (upstream, upstream_hits) = spawn_raw_h1_upstream(response).await;
    let state = test_state(upstream).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;
    let mut request_stream = timeout(
        Duration::from_secs(5),
        send_request.send_request(Request::get("https://localhost/ok").body(()).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    request_stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(5), request_stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let body = timeout(Duration::from_secs(5), request_stream.recv_data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(body.chunk());
    assert!(text.contains("HW-NATIVE-DLP-002"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_request_trailer_dlp_blocks_private_key_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.routes[0].grpc = true;
        config.bans.enabled = false;
    })
    .await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;
    let request = Request::post("https://localhost/ok")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let mut request_stream = timeout(Duration::from_secs(5), send_request.send_request(request))
        .await
        .unwrap()
        .unwrap();
    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        "x-secret",
        http::HeaderValue::from_static("-----BEGIN PRIVATE KEY----- AAAA"),
    );
    request_stream.send_trailers(trailers).await.unwrap();
    request_stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(5), request_stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let body = timeout(Duration::from_secs(5), request_stream.recv_data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(body.chunk());
    assert!(text.contains("HW-NATIVE-DLP-002"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_grpc_response_body_dlp_blocks_private_key_material() {
    let secret = b"-----BEGIN PRIVATE KEY-----\nAAAA\n";
    let (upstream, upstream_hits) = spawn_h2_upstream(grpc_frame(secret), Vec::new()).await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.routes[0].grpc = true;
        config.bans.enabled = false;
    })
    .await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;
    let request = Request::post("https://localhost/ok")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let mut request_stream = timeout(Duration::from_secs(5), send_request.send_request(request))
        .await
        .unwrap()
        .unwrap();
    request_stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(5), request_stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let body = timeout(Duration::from_secs(5), request_stream.recv_data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(body.chunk());
    assert!(text.contains("HW-NATIVE-DLP-002"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_grpc_response_trailer_dlp_blocks_private_key_material() {
    let (upstream, upstream_hits) = spawn_h2_upstream(
        grpc_frame(b"ok"),
        vec![("x-secret", "-----BEGIN PRIVATE KEY----- AAAA")],
    )
    .await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.routes[0].grpc = true;
        config.bans.enabled = false;
    })
    .await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;
    let request = Request::post("https://localhost/ok")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let mut request_stream = timeout(Duration::from_secs(5), send_request.send_request(request))
        .await
        .unwrap()
        .unwrap();
    request_stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(5), request_stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    let body = timeout(Duration::from_secs(5), request_stream.recv_data())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8_lossy(body.chunk());
    assert!(text.contains("HW-NATIVE-DLP-002"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_request_dlp_blocks_private_key_material_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state(upstream).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;
    let mut request_stream = timeout(
        Duration::from_secs(5),
        send_request.send_request(Request::get("https://localhost/ok").body(()).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    request_stream
        .send_data(Bytes::from_static(b"-----BEGIN PRIVATE KEY-----\nAAAA\n"))
        .await
        .unwrap();
    request_stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(5), request_stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_request_dlp_blocks_high_entropy_secret_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.bans.enabled = false;
    })
    .await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;
    let mut request_stream = timeout(
        Duration::from_secs(5),
        send_request.send_request(Request::post("https://localhost/ok").body(()).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    request_stream
        .send_data(Bytes::from_static(HIGH_ENTROPY_SECRET.as_bytes()))
        .await
        .unwrap();
    request_stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(5), request_stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_shutdown_is_bounded_when_a_request_body_stalls() {
    let upstream = spawn_h1_upstream().await;
    let state = test_state(upstream).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;

    let request = Request::get("https://localhost/ok").body(()).unwrap();
    let mut request_stream = timeout(Duration::from_secs(5), send_request.send_request(request))
        .await
        .unwrap()
        .unwrap();
    request_stream
        .send_data(Bytes::from_static(b"partial body"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = tokio::time::Instant::now();
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(8), server)
        .await
        .expect("HTTP/3 shutdown must respect its deadline")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(7));
    drop(request_stream);
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_reset_budget_closes_the_connection_without_upstream_traffic() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.limits.max_h3_reset_errors = 2;
        config.limits.max_h3_streams = 8;
        config.bans.enabled = false;
    })
    .await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;

    let mut sent = 0;
    for _ in 0..16 {
        let request = Request::get("https://localhost/ok").body(()).unwrap();
        let Ok(Ok(mut request_stream)) =
            timeout(Duration::from_secs(5), send_request.send_request(request)).await
        else {
            break;
        };
        request_stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        sent += 1;
        tokio::task::yield_now().await;
    }
    assert!(sent >= 3, "the reset flood never reached the server");
    timeout(Duration::from_secs(8), server)
        .await
        .expect("HTTP/3 reset budget must close the connection")
        .unwrap()
        .unwrap();
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = shutdown_tx.send(true);
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test]
async fn h3_unknown_alpn_does_not_fall_back() {
    let (certificate, key) = test_certificate();
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate.clone()], key)
    .unwrap();
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    server_crypto.max_early_data_size = 0;
    let server_config =
        h3_server::build_quic_server_config(&QuicConfig::default(), &server_crypto).unwrap();
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        if let Ok(connecting) = incoming.accept() {
            assert!(timeout(Duration::from_secs(5), connecting)
                .await
                .unwrap()
                .is_err());
        }
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap();
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
    let result = timeout(
        Duration::from_secs(5),
        client_endpoint
            .connect(server_address, "localhost")
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(
        result.is_err(),
        "unknown ALPN must not negotiate a fallback"
    );
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    server.await.unwrap();
}

async fn test_state(upstream: SocketAddr) -> Arc<AppState> {
    test_state_with(upstream, |_| {}).await
}

async fn test_state_with(
    upstream: SocketAddr,
    configure: impl FnOnce(&mut AppConfig),
) -> Arc<AppState> {
    let mut config = AppConfig::default();
    config.audit.enabled = false;
    config.agent.enabled = false;
    config.routes = vec![RouteConfig {
        name: "ok".to_string(),
        path_prefix: "/ok".to_string(),
        methods: vec!["GET".to_string()],
        upstream: Some(UpstreamConfig {
            host: upstream.ip().to_string(),
            port: upstream.port(),
            ..UpstreamConfig::default()
        }),
        ..RouteConfig::default()
    }];
    configure(&mut config);
    AppState::new(config).await.unwrap()
}

async fn spawn_h1_upstream() -> SocketAddr {
    spawn_counted_h1_upstream().await.0
}

async fn spawn_counted_h1_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    spawn_h1_upstream_with_body(b"ok").await
}

async fn spawn_h1_upstream_with_body(body: &'static [u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect();
    spawn_raw_h1_upstream(response).await
}

async fn spawn_raw_h1_upstream(response: Vec<u8>) -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task_hits = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let request_hits = task_hits.clone();
            let response = response.clone();
            tokio::spawn(async move {
                request_hits.fetch_add(1, Ordering::SeqCst);
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let _ = stream.write_all(&response).await;
            });
        }
    });
    (address, hits)
}

fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes()[1..]);
    frame.push(frame_type);
    frame.push(flags);
    frame.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn read_h2_frame(stream: &mut tokio::io::DuplexStream) -> (u8, u8, u32, Vec<u8>) {
    let mut header = [0_u8; 9];
    timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .expect("timed out reading an HTTP/2 frame header")
        .expect("failed to read an HTTP/2 frame header");
    let length =
        (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    let mut payload = vec![0_u8; length];
    if length != 0 {
        timeout(Duration::from_secs(5), stream.read_exact(&mut payload))
            .await
            .expect("timed out reading an HTTP/2 frame payload")
            .expect("failed to read an HTTP/2 frame payload");
    }
    let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
    (header[3], header[4], stream_id, payload)
}

async fn read_h2_goaway(stream: &mut tokio::io::DuplexStream) -> (u32, u32) {
    for _ in 0..32 {
        let (frame_type, _flags, _stream_id, payload) = read_h2_frame(stream).await;
        if frame_type == 0x7 {
            assert!(payload.len() >= 8, "GOAWAY payload was too short");
            let last_stream_id =
                u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
            let error_code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            return (last_stream_id, error_code);
        }
    }
    panic!("server did not send GOAWAY");
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(5 + payload.len());
    body.push(0);
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend_from_slice(payload);
    body
}

async fn spawn_h2_upstream(
    body: Vec<u8>,
    trailers: Vec<(&'static str, &'static str)>,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task_hits = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let request_hits = task_hits.clone();
            let body = body.clone();
            let trailers = trailers.clone();
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(stream).await else {
                    return;
                };
                while let Some(Ok((_request, mut respond))) = connection.accept().await {
                    request_hits.fetch_add(1, Ordering::SeqCst);
                    let response = http::Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let end_stream = body.is_empty() && trailers.is_empty();
                    let Ok(mut send) = respond.send_response(response, end_stream) else {
                        return;
                    };
                    if !body.is_empty()
                        && send
                            .send_data(Bytes::copy_from_slice(&body), trailers.is_empty())
                            .is_err()
                    {
                        return;
                    }
                    if !trailers.is_empty() {
                        let mut fields = http::HeaderMap::new();
                        for &(name, value) in &trailers {
                            fields.append(
                                http::HeaderName::from_static(name),
                                http::HeaderValue::from_static(value),
                            );
                        }
                        if send.send_trailers(fields).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    (address, hits)
}

async fn spawn_h3_test_server(
    state: Arc<AppState>,
    shutdown_rx: watch::Receiver<bool>,
) -> (
    SocketAddr,
    rustls::pki_types::CertificateDer<'static>,
    tokio::task::JoinHandle<highwall_native_core::error::Result<()>>,
) {
    let (certificate, key) = test_certificate();
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate.clone()], key)
    .unwrap();
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    server_crypto.max_early_data_size = 0;
    let quic = QuicConfig::default();
    let server_config = h3_server::build_quic_server_config(&quic, &server_crypto).unwrap();
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_address = server_endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let connection = timeout(Duration::from_secs(5), incoming)
            .await
            .unwrap()
            .unwrap();
        h3_server::serve_connection(
            connection,
            "127.0.0.1:40002".parse().unwrap(),
            tls_info("h3"),
            state,
            shutdown_rx,
        )
        .await
    });
    (server_address, certificate, server)
}

async fn connect_h3_test_client(
    server_address: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
) -> (
    quinn::Endpoint,
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    tokio::task::JoinHandle<()>,
) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let connection = timeout(
        Duration::from_secs(5),
        client_endpoint
            .connect(server_address, "localhost")
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    (client_endpoint, send_request, driver_task)
}

fn tls_info(alpn: &str) -> TlsConnectionInfo {
    TlsConnectionInfo {
        server_name: Some("localhost".to_string()),
        version: Some("TLS1.3".to_string()),
        alpn: Some(alpn.to_string()),
    }
}

fn test_certificate() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (
        generated.cert.into(),
        rustls::pki_types::PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into()),
    )
}
