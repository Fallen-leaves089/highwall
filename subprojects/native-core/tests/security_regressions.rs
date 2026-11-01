use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
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
    time::timeout,
};

const JWT: &str =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl";
const GOOGLE_KEY: &str = "AIzaA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1x";

#[tokio::test]
async fn h1_ten_kib_header_line_is_rejected_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.limits.max_head_bytes = 32 * 1024;
        config.limits.max_header_line_bytes = 8 * 1024;
    })
    .await;
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(h1_server::serve_connection(
        server_io,
        "127.0.0.1:41001".parse().unwrap(),
        tls_info("http/1.1"),
        state,
    ));

    let mut request = b"GET /ok HTTP/1.1\r\nHost: localhost\r\nX-Large: ".to_vec();
    request.extend(std::iter::repeat_n(b'a', 10 * 1024));
    request.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    client.write_all(&request).await.unwrap();

    let mut response = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert!(response.contains("HW-NATIVE-PROTOCOL-001"), "{response}");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = server.await.unwrap();
}

#[tokio::test]
async fn h1_chunked_trailers_are_rejected_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
    })
    .await;
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(h1_server::serve_connection(
        server_io,
        "127.0.0.1:41002".parse().unwrap(),
        tls_info("http/1.1"),
        state,
    ));

    client
        .write_all(
            b"POST /ok HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n0\r\nX-Checksum: 1\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(response.contains("HW-NATIVE-PROTOCOL-002"), "{response}");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = server.await.unwrap();
}

#[tokio::test]
async fn h1_single_chunked_body_is_accepted_and_reaches_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
    })
    .await;
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(h1_server::serve_connection(
        server_io,
        "127.0.0.1:41006".parse().unwrap(),
        tls_info("http/1.1"),
        state,
    ));

    client
        .write_all(
            b"POST /ok HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\ntest\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("ok"), "{response}");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    let _ = server.await.unwrap();
}

#[tokio::test]
async fn h1_header_borne_waf_payload_is_rejected_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.bans.enabled = false;
    })
    .await;
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(h1_server::serve_connection(
        server_io,
        "127.0.0.1:41007".parse().unwrap(),
        tls_info("http/1.1"),
        state,
    ));

    client
        .write_all(
            b"GET /ok HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-Host: <script>alert(1)</script>\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(response.contains("HW-NATIVE-WAF-003"), "{response}");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = server.await.unwrap();
}

#[tokio::test]
async fn h1_ban_remains_observable_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].path_prefix = "/".to_string();
        config.bans.enabled = true;
        config.bans.ttl_seconds = 60;
        config.bans.max_ttl_seconds = 60;
        config.bans.violation_threshold = 2;
        config.bans.violation_window_seconds = 60;
    })
    .await;
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(h1_server::serve_connection(
        server_io,
        "127.0.0.1:41009".parse().unwrap(),
        tls_info("http/1.1"),
        state,
    ));

    client
        .write_all(
            b"GET /.git/HEAD HTTP/1.1\r\nHost: localhost\r\n\r\nGET /.git/HEAD HTTP/1.1\r\nHost: localhost\r\n\r\nGET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response);
    assert_eq!(response.matches("HTTP/1.1 403").count(), 3, "{response}");
    assert!(response.contains("HW-NATIVE-WAF-006"), "{response}");
    assert!(response.contains("HW-NATIVE-BAN-001"), "{response}");
    assert!(response.contains("retry-after:"), "{response}");
    assert!(
        response.contains("x-ratelimit-policy: highwall-source-ban"),
        "{response}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = server.await.unwrap();
}

#[tokio::test]
async fn h1_high_entropy_secret_is_rejected_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.bans.enabled = false;
    })
    .await;
    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(h1_server::serve_connection(
        server_io,
        "127.0.0.1:41008".parse().unwrap(),
        tls_info("http/1.1"),
        state,
    ));

    let body = "api_key=5a13c8817e37eca512cb807936efa41dca837831eea71cd5827b30e9a61fd48d";
    let request = format!(
        "POST /ok HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 451"), "{response}");
    assert!(response.contains("HW-NATIVE-DLP-004"), "{response}");
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let _ = server.await.unwrap();
}

#[tokio::test]
async fn h2_request_dlp_blocks_jwt_and_google_api_key() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.routes[0].dlp = true;
        config.bans.enabled = false;
    })
    .await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:41003".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    for body in [JWT, GOOGLE_KEY] {
        let request = Request::post("https://localhost/ok")
            .header("host", "localhost")
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        let (response, mut send_stream) = client.send_request(request, false).unwrap();
        send_stream
            .send_data(Bytes::copy_from_slice(body.as_bytes()), true)
            .unwrap();
        let response = timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        let response_body = read_h2_body(response.into_body()).await;
        let text = String::from_utf8_lossy(&response_body);
        assert!(text.contains("HW-NATIVE-DLP-003"), "{text}");
        assert!(
            !text.contains(body),
            "DLP response leaked the submitted secret"
        );
    }
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
async fn h2_response_dlp_blocks_google_api_key() {
    let (upstream, upstream_hits) = spawn_h1_upstream_with_body(GOOGLE_KEY.as_bytes()).await;
    let state = test_state(upstream).await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:41004".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = Request::get("https://localhost/ok")
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
    let response_body = read_h2_body(response.into_body()).await;
    let text = String::from_utf8_lossy(&response_body);
    assert!(text.contains("HW-NATIVE-DLP-003"), "{text}");
    assert!(
        !text.contains(GOOGLE_KEY),
        "DLP response leaked the upstream key"
    );
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
async fn h2_response_dlp_uses_an_independent_ban_threshold() {
    let (upstream, upstream_hits) = spawn_h1_upstream_with_body(GOOGLE_KEY.as_bytes()).await;
    let state = test_state_with(upstream, |config| {
        config.bans.enabled = true;
        config.bans.violation_threshold = 1;
        config.bans.violation_window_seconds = 60;
        config.bans.response_violation_threshold = 2;
        config.bans.response_violation_window_seconds = 60;
        config.bans.ttl_seconds = 60;
        config.bans.max_ttl_seconds = 60;
    })
    .await;
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(h2_server::serve_connection(
        server_io,
        "127.0.0.1:41005".parse().unwrap(),
        tls_info("h2"),
        state,
        shutdown_rx,
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    for (index, expected) in [StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS; 2]
        .into_iter()
        .enumerate()
    {
        let request = Request::get("https://localhost/ok")
            .header("host", "localhost")
            .body(())
            .unwrap();
        let (response, send_stream) = client.send_request(request, true).unwrap();
        drop(send_stream);
        let response = timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), expected);
        if index == 1 {
            assert!(response.headers().get("retry-after").is_some());
            assert_eq!(
                response
                    .headers()
                    .get("x-ratelimit-policy")
                    .and_then(|value| value.to_str().ok()),
                Some("highwall-source-ban")
            );
        }
        let body = read_h2_body(response.into_body()).await;
        assert!(String::from_utf8_lossy(&body).contains("HW-NATIVE-DLP-003"));
    }
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 2);

    let request = Request::get("https://localhost/ok")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, send_stream) = client.send_request(request, true).unwrap();
    drop(send_stream);
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get("retry-after").is_some());
    assert_eq!(
        response
            .headers()
            .get("x-ratelimit-policy")
            .and_then(|value| value.to_str().ok()),
        Some("highwall-source-ban")
    );
    let body = read_h2_body(response.into_body()).await;
    assert!(String::from_utf8_lossy(&body).contains("HW-NATIVE-BAN-001"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 2);

    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.abort();
}

#[tokio::test]
async fn h3_request_dlp_blocks_jwt_and_google_api_key() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state_with(upstream, |config| {
        config.routes[0].methods = vec!["POST".to_string()];
        config.routes[0].dlp = true;
        config.bans.enabled = false;
    })
    .await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, mut send_request, driver_task) =
        connect_h3_test_client(server_address, certificate).await;

    for body in [JWT, GOOGLE_KEY] {
        let request = Request::post("https://localhost/ok")
            .header("content-type", "text/plain")
            .body(())
            .unwrap();
        let mut request_stream =
            timeout(Duration::from_secs(5), send_request.send_request(request))
                .await
                .unwrap()
                .unwrap();
        request_stream
            .send_data(Bytes::copy_from_slice(body.as_bytes()))
            .await
            .unwrap();
        request_stream.finish().await.unwrap();
        let response = timeout(Duration::from_secs(5), request_stream.recv_response())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
        let response_body = read_h3_body(&mut request_stream).await;
        let text = String::from_utf8_lossy(&response_body);
        assert!(text.contains("HW-NATIVE-DLP-003"), "{text}");
        assert!(
            !text.contains(body),
            "DLP response leaked the submitted secret"
        );
    }
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
async fn h3_response_dlp_blocks_jwt() {
    let (upstream, upstream_hits) = spawn_h1_upstream_with_body(JWT.as_bytes()).await;
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
    let response_body = read_h3_body(&mut request_stream).await;
    let text = String::from_utf8_lossy(&response_body);
    assert!(text.contains("HW-NATIVE-DLP-003"), "{text}");
    assert!(
        !text.contains(JWT),
        "DLP response leaked the upstream token"
    );
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
async fn h3_raw_qpack_valid_request_is_a_positive_control() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state(upstream).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, connection) = connect_raw_h3_client(server_address, certificate).await;

    let response = send_raw_h3_headers(&connection, &qpack_request_block(false)).await;
    assert!(
        response.as_ref().is_ok_and(|bytes| !bytes.is_empty()),
        "the positive-control raw HTTP/3 request did not receive a response: {response:?}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
}

#[tokio::test]
async fn h3_raw_qpack_duplicate_pseudo_header_is_rejected_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state(upstream).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, connection) = connect_raw_h3_client(server_address, certificate).await;

    let error = send_raw_h3_headers(&connection, &qpack_request_block(true))
        .await
        .expect_err("duplicate pseudo-header was accepted");
    assert!(
        matches!(error, RawH3Error::Reset(code) if code == quinn::VarInt::from_u32(270)),
        "duplicate pseudo-header must use H3_MESSAGE_ERROR (0x10E): {error:?}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
}

#[tokio::test]
async fn h3_missing_authority_returns_bad_request_and_message_error_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let audit_path = test_audit_path("h3-authority-missing");
    let state = test_state_with(upstream, |config| {
        config.audit.enabled = true;
        config.audit.path = audit_path.clone();
    })
    .await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, connection) = connect_raw_h3_client(server_address, certificate).await;

    let response =
        send_raw_h3_headers_observing_stop(&connection, &qpack_request_block_without_authority())
            .await
            .expect("request without :authority did not produce an observable response");
    assert_eq!(decode_h3_response_status(&response.bytes), Some(400));
    assert_eq!(response.stop_sending, Some(quinn::VarInt::from_u32(270)));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let event = read_audit_event(&audit_path).await;
    assert_authority_audit(&event, "HW-NATIVE-H3-AUTHORITY-001", "missing", "sent", &[]);

    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    cleanup_audit_file(&audit_path).await;
}

#[tokio::test]
async fn h3_duplicate_method_is_reset_with_h3_message_error_before_upstream() {
    assert_h3_pseudo_header_rejection(qpack_request_block_duplicate_method(), "duplicate :method")
        .await;
}

#[tokio::test]
async fn h3_duplicate_authority_is_reset_with_h3_message_error_before_upstream() {
    assert_h3_pseudo_header_rejection(
        qpack_request_block_duplicate_authority(),
        "duplicate :authority",
    )
    .await;
}

#[tokio::test]
async fn h3_host_authority_mismatch_returns_bad_request_and_message_error_before_upstream() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let audit_path = test_audit_path("h3-authority-mismatch");
    let state = test_state_with(upstream, |config| {
        config.audit.enabled = true;
        config.audit.path = audit_path.clone();
    })
    .await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, connection) = connect_raw_h3_client(server_address, certificate).await;
    let response =
        send_raw_h3_headers_observing_stop(&connection, &qpack_request_block_host_mismatch())
            .await
            .expect("Host/:authority mismatch did not produce an observable response");
    assert_eq!(decode_h3_response_status(&response.bytes), Some(400));
    assert_eq!(response.stop_sending, Some(quinn::VarInt::from_u32(270)));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let event = read_audit_event(&audit_path).await;
    assert_authority_audit(
        &event,
        "HW-NATIVE-H3-AUTHORITY-002",
        "mismatch",
        "sent",
        &["localhost", "evil.example"],
    );

    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    cleanup_audit_file(&audit_path).await;
}

#[tokio::test]
async fn h3_missing_authority_falls_back_to_reset_when_bad_request_cannot_be_sent() {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let audit_path = test_audit_path("h3-authority-fallback");
    let state = test_state_with(upstream, |config| {
        config.audit.enabled = true;
        config.audit.path = audit_path.clone();
    })
    .await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, connection) = connect_raw_h3_client(server_address, certificate).await;

    let stop_sending = send_raw_h3_headers_after_stopping_response(
        &connection,
        &qpack_request_block_without_authority(),
    )
    .await
    .expect("fallback rejection did not terminate the request stream");
    assert_eq!(stop_sending, Some(quinn::VarInt::from_u32(270)));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    let event = read_audit_event(&audit_path).await;
    assert_authority_audit(
        &event,
        "HW-NATIVE-H3-AUTHORITY-001",
        "missing",
        "failed",
        &[],
    );

    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    cleanup_audit_file(&audit_path).await;
}

async fn assert_h3_pseudo_header_rejection(field_block: Vec<u8>, label: &str) {
    let (upstream, upstream_hits) = spawn_counted_h1_upstream().await;
    let state = test_state(upstream).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (server_address, certificate, server) = spawn_h3_test_server(state, shutdown_rx).await;
    let (client_endpoint, connection) = connect_raw_h3_client(server_address, certificate).await;
    let error = send_raw_h3_headers(&connection, &field_block)
        .await
        .expect_err("malformed HTTP/3 pseudo-headers were accepted");
    assert!(
        matches!(error, RawH3Error::Reset(code) if code == quinn::VarInt::from_u32(270)),
        "{label} must use H3_MESSAGE_ERROR (0x10E): {error}"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);

    let _ = shutdown_tx.send(true);
    timeout(Duration::from_secs(8), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
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
        dlp: true,
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

async fn spawn_counted_h1_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    spawn_h1_upstream_with_body(b"ok").await
}

async fn spawn_h1_upstream_with_body(body: &[u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect::<Vec<_>>();
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

async fn read_h2_body(mut body: h2::RecvStream) -> Vec<u8> {
    let mut received = Vec::new();
    while let Some(Ok(chunk)) = timeout(Duration::from_secs(5), body.data()).await.unwrap() {
        received.extend_from_slice(&chunk);
    }
    received
}

async fn read_h3_body(
    stream: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Vec<u8> {
    let mut received = Vec::new();
    while let Some(chunk) = timeout(Duration::from_secs(5), stream.recv_data())
        .await
        .unwrap()
        .unwrap()
    {
        received.extend_from_slice(chunk.chunk());
    }
    received
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
    let server_config =
        h3_server::build_quic_server_config(&QuicConfig::default(), &server_crypto).unwrap();
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let incoming = timeout(Duration::from_secs(5), endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let connection = timeout(Duration::from_secs(5), incoming)
            .await
            .unwrap()
            .unwrap();
        h3_server::serve_connection(
            connection,
            "127.0.0.1:41005".parse().unwrap(),
            tls_info("h3"),
            state,
            shutdown_rx,
        )
        .await
    });
    (address, certificate, server)
}

async fn connect_h3_test_client(
    server_address: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
) -> (
    quinn::Endpoint,
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    tokio::task::JoinHandle<()>,
) {
    let (endpoint, connection) = connect_raw_h3_client(server_address, certificate).await;
    let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    (endpoint, send_request, driver_task)
}

async fn connect_raw_h3_client(
    server_address: SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
) -> (quinn::Endpoint, quinn::Connection) {
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
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    let connection = timeout(
        Duration::from_secs(5),
        endpoint.connect(server_address, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    (endpoint, connection)
}

async fn send_raw_h3_headers(
    connection: &quinn::Connection,
    field_block: &[u8],
) -> std::result::Result<Vec<u8>, RawH3Error> {
    let RawH3Request {
        mut send,
        mut recv,
        _control,
        _encoder,
        _decoder,
    } = open_raw_h3_request(connection).await?;
    let frame = h3_frame(0x01, field_block);
    send.write_all(&frame)
        .await
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    send.finish()
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;

    let response = timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024))
        .await
        .map_err(|_| RawH3Error::Transport("response timed out".to_string()))?
        .map_err(map_read_to_end_error)?;
    Ok(response)
}

struct RawH3HttpResponse {
    bytes: Vec<u8>,
    stop_sending: Option<quinn::VarInt>,
}

async fn send_raw_h3_headers_observing_stop(
    connection: &quinn::Connection,
    field_block: &[u8],
) -> std::result::Result<RawH3HttpResponse, RawH3Error> {
    let RawH3Request {
        mut send,
        mut recv,
        _control,
        _encoder,
        _decoder,
    } = open_raw_h3_request(connection).await?;
    let frame = h3_frame(0x01, field_block);
    send.write_all(&frame)
        .await
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;

    let (response, stopped) = tokio::join!(
        timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024)),
        timeout(Duration::from_secs(5), send.stopped()),
    );
    let bytes = response
        .map_err(|_| RawH3Error::Transport("response timed out".to_string()))?
        .map_err(map_read_to_end_error)?;
    let stop_sending = stopped
        .map_err(|_| RawH3Error::Transport("stop-sending observation timed out".to_string()))?
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    Ok(RawH3HttpResponse {
        bytes,
        stop_sending,
    })
}

async fn send_raw_h3_headers_after_stopping_response(
    connection: &quinn::Connection,
    field_block: &[u8],
) -> std::result::Result<Option<quinn::VarInt>, RawH3Error> {
    let RawH3Request {
        mut send,
        mut recv,
        _control,
        _encoder,
        _decoder,
    } = open_raw_h3_request(connection).await?;
    recv.stop(quinn::VarInt::from_u32(270))
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    let frame = h3_frame(0x01, field_block);
    send.write_all(&frame)
        .await
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    timeout(Duration::from_secs(5), send.stopped())
        .await
        .map_err(|_| RawH3Error::Transport("stop-sending observation timed out".to_string()))?
        .map_err(|error| RawH3Error::Transport(error.to_string()))
}

struct RawH3Request {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    _control: quinn::SendStream,
    _encoder: quinn::SendStream,
    _decoder: quinn::SendStream,
}

async fn open_raw_h3_request(
    connection: &quinn::Connection,
) -> std::result::Result<RawH3Request, RawH3Error> {
    let mut control = connection
        .open_uni()
        .await
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    control
        .write_all(&[0x00, 0x04, 0x00])
        .await
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    let mut encoder = connection
        .open_uni()
        .await
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    encoder
        .write_all(&[0x02])
        .await
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    let mut decoder = connection
        .open_uni()
        .await
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    decoder
        .write_all(&[0x03])
        .await
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|error| RawH3Error::Transport(error.to_string()))?;
    Ok(RawH3Request {
        send,
        recv,
        _control: control,
        _encoder: encoder,
        _decoder: decoder,
    })
}

fn map_read_to_end_error(error: quinn::ReadToEndError) -> RawH3Error {
    match error {
        quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)) => RawH3Error::Reset(code),
        other => RawH3Error::Transport(other.to_string()),
    }
}

#[derive(Debug)]
enum RawH3Error {
    Reset(quinn::VarInt),
    Transport(String),
}

impl std::fmt::Display for RawH3Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reset(code) => write!(formatter, "stream reset with code {code}"),
            Self::Transport(detail) => formatter.write_str(detail),
        }
    }
}

fn decode_h3_response_status(bytes: &[u8]) -> Option<u16> {
    let mut remaining = bytes;
    let frame_type = decode_varint(&mut remaining)?;
    if frame_type != 0x01 {
        return None;
    }
    let length = decode_varint(&mut remaining)? as usize;
    if remaining.len() < length {
        return None;
    }
    decode_qpack_status(&remaining[..length])
}

fn decode_qpack_status(block: &[u8]) -> Option<u16> {
    let mut cursor = 0;
    decode_prefixed_int(block, &mut cursor, 8)?;
    decode_prefixed_int(block, &mut cursor, 7)?;
    let (flags, index) = decode_prefixed_int(block, &mut cursor, 6)?;
    if flags != 0b11 {
        return None;
    }
    (index == 67).then_some(400)
}

fn decode_prefixed_int(data: &[u8], cursor: &mut usize, prefix_bits: u8) -> Option<(u8, u64)> {
    let first = *data.get(*cursor)? as u32;
    *cursor += 1;
    let flags = (first >> prefix_bits) as u8;
    let mask = 0xFFu32 >> (8 - prefix_bits);
    let mut value = (first & mask) as u64;
    if value < mask as u64 {
        return Some((flags, value));
    }
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*cursor)?;
        *cursor += 1;
        value = value.checked_add(((byte & 0x7F) as u64).checked_shl(shift)?)?;
        if byte & 0x80 == 0 {
            return Some((flags, value));
        }
        shift = shift.checked_add(7)?;
    }
}

fn decode_varint(input: &mut &[u8]) -> Option<u64> {
    let first = *input.first()?;
    let length = 1usize << (first >> 6);
    if input.len() < length {
        return None;
    }
    let mut value = (first & 0x3F) as u64;
    for byte in &input[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    *input = &input[length..];
    Some(value)
}

fn test_audit_path(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "highwall-native-{}-{}.jsonl",
        label,
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

async fn read_audit_event(path: &Path) -> serde_json::Value {
    timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                if let Some(line) = content.lines().find(|line| !line.trim().is_empty()) {
                    if let Ok(event) = serde_json::from_str(line) {
                        return event;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("audit event timed out")
}

fn assert_authority_audit(
    event: &serde_json::Value,
    rule: &str,
    kind: &str,
    response_result: &str,
    raw_values: &[&str],
) {
    assert_eq!(event["status"].as_u64(), Some(400));
    assert_eq!(event["decision"].as_str(), Some("deny"));
    assert_eq!(event["rule_ids"][0].as_str(), Some(rule));
    let detail = event["detail"].as_str().expect("audit detail");
    assert!(
        detail.contains(&format!("h3_authority_error={kind}")),
        "{detail}"
    );
    assert!(
        detail.contains(&format!("response_result={response_result}")),
        "{detail}"
    );
    assert!(
        detail.contains("protocol_error=H3_MESSAGE_ERROR(0x10E)"),
        "{detail}"
    );
    assert!(detail.contains("upstream_reached=false"), "{detail}");
    for raw_value in raw_values {
        assert!(
            !detail.contains(raw_value),
            "audit detail leaked raw host value {raw_value}: {detail}"
        );
    }
}

async fn cleanup_audit_file(path: &Path) {
    for _ in 0..40 {
        if tokio::fs::remove_file(path).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn qpack_request_block(duplicate_path: bool) -> Vec<u8> {
    let mut block = vec![0x00, 0x00, 0xd1, 0xd7, 0x50, 0x09];
    block.extend_from_slice(b"localhost");
    block.extend_from_slice(&[0x51, 0x03, b'/', b'o', b'k']);
    if duplicate_path {
        block.extend_from_slice(&[0x51, 0x03, b'/', b'o', b'k']);
    }
    block
}

fn qpack_request_block_without_authority() -> Vec<u8> {
    let mut block = vec![0x00, 0x00, 0xd1, 0xd7, 0x51, 0x03];
    block.extend_from_slice(b"/ok");
    block
}

fn qpack_request_block_duplicate_method() -> Vec<u8> {
    let mut block = qpack_request_block(false);
    block.push(0xd1);
    block
}

fn qpack_request_block_duplicate_authority() -> Vec<u8> {
    let mut block = qpack_request_block(false);
    block.extend_from_slice(&[0x50, 0x09]);
    block.extend_from_slice(b"localhost");
    block
}

fn qpack_request_block_host_mismatch() -> Vec<u8> {
    let mut block = qpack_request_block(false);
    block.extend_from_slice(&[0x24]);
    block.extend_from_slice(b"host");
    block.push(12);
    block.extend_from_slice(b"evil.example");
    block
}

fn h3_frame(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 8);
    encode_varint(frame_type, &mut frame);
    encode_varint(payload.len() as u64, &mut frame);
    frame.extend_from_slice(payload);
    frame
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    if value < 64 {
        output.push(value as u8);
    } else if value < 16_384 {
        output.extend_from_slice(&((value | 0x4000) as u16).to_be_bytes());
    } else if value < 1_073_741_824 {
        output.extend_from_slice(&((value | 0x8000_0000) as u32).to_be_bytes());
    } else {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
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
