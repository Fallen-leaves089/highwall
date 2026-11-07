use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, Bytes};
use highwall_native_core::config::{
    AgentConfig, AppConfig, BanConfig, MtlsMode, ProxyProtocolConfig, ProxyProtocolMode,
    QuicConfig, TlsConfig, TlsMinVersion,
};
use ipnet::IpNet;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason,
    RevokedCertParams, SerialNumber,
};
use rustls::pki_types::CertificateDer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    task::JoinHandle,
    time::{sleep, timeout, Instant},
};

struct LiveServer {
    child: Child,
    tcp: SocketAddr,
    quic: SocketAddr,
    certificate: CertificateDer<'static>,
    upstream_hits: Arc<AtomicUsize>,
    upstream: JoinHandle<()>,
    audit_path: PathBuf,
}

static SERVER_START_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

impl Drop for LiveServer {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        self.upstream.abort();
    }
}

async fn start_server() -> LiveServer {
    start_server_with_proxy(ProxyProtocolConfig::default()).await
}

async fn start_server_with_proxy(proxy_protocol: ProxyProtocolConfig) -> LiveServer {
    start_server_with_options(proxy_protocol, None, None, Vec::new(), |_| {}).await
}

async fn start_server_with_quic_host(host: IpAddr) -> LiveServer {
    start_server_with_options(
        ProxyProtocolConfig::default(),
        None,
        Some(host),
        Vec::new(),
        |_| {},
    )
    .await
}

async fn start_server_with_quic_acl(networks: Vec<IpNet>) -> LiveServer {
    start_server_with_options(ProxyProtocolConfig::default(), None, None, networks, |_| {}).await
}

async fn start_server_with_mtls(client_ca_pem: String, client_crl_der: Vec<u8>) -> LiveServer {
    start_server_with_options(
        ProxyProtocolConfig::default(),
        Some((client_ca_pem, client_crl_der)),
        None,
        Vec::new(),
        |_| {},
    )
    .await
}

async fn start_server_with_options(
    proxy_protocol: ProxyProtocolConfig,
    mtls: Option<(String, Vec<u8>)>,
    quic_host: Option<IpAddr>,
    quic_allowed_client_networks: Vec<IpNet>,
    configure: impl FnOnce(&mut AppConfig),
) -> LiveServer {
    let _start_guard = SERVER_START_LOCK.lock().await;
    let (upstream, upstream_hits, upstream_task) = spawn_upstream().await;
    let tcp_port = free_tcp_port();
    let quic_port = free_udp_port();
    let directory = test_directory();
    std::fs::create_dir_all(&directory).unwrap();

    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let certificate = generated.cert.der().clone();
    let cert_path = directory.join("server-cert.pem");
    let key_path = directory.join("server-key.pem");
    std::fs::write(&cert_path, generated.cert.pem()).unwrap();
    std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();

    let mut config = AppConfig::default();
    config.listen.port = tcp_port;
    config.listen.proxy_protocol = proxy_protocol;
    config.upstream.host = upstream.ip().to_string();
    config.upstream.port = upstream.port();
    config.audit.path = directory.join("native-audit.jsonl");
    config.agent = AgentConfig {
        enabled: false,
        ..AgentConfig::default()
    };
    config.bans = BanConfig {
        enabled: false,
        ..BanConfig::default()
    };
    config.limits.tls_handshake_timeout_ms = 1_000;
    config.tls = Some(TlsConfig {
        cert_file: cert_path,
        key_file: key_path,
        require_private_key_permissions: false,
        min_version: TlsMinVersion::Tls13,
        validate_certificate: false,
        allowed_sni: vec!["localhost".to_string()],
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        ..TlsConfig::default()
    });
    if let Some((client_ca_pem, client_crl_der)) = mtls {
        let ca_path = directory.join("client-ca.pem");
        let crl_path = directory.join("client-crl.der");
        std::fs::write(&ca_path, client_ca_pem).unwrap();
        std::fs::write(&crl_path, client_crl_der).unwrap();
        let tls = config.tls.as_mut().unwrap();
        tls.mtls = MtlsMode::Required;
        tls.client_ca_file = Some(ca_path);
        tls.client_crl_file = Some(crl_path);
    }
    config.quic = Some(QuicConfig {
        enabled: true,
        host: quic_host,
        listen_port: quic_port,
        allowed_client_networks: quic_allowed_client_networks,
        require_retry: true,
        allow_migration: false,
        ..QuicConfig::default()
    });
    configure(&mut config);

    let config_path = directory.join("highwall-native.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_highwall-native-core"))
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    let tcp = SocketAddr::from(([127, 0, 0, 1], tcp_port));
    wait_for_tcp(tcp).await;
    LiveServer {
        child,
        tcp,
        quic: SocketAddr::new(
            quic_host.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            quic_port,
        ),
        certificate,
        upstream_hits,
        upstream: upstream_task,
        audit_path: directory.join("native-audit.jsonl"),
    }
}

async fn spawn_upstream() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let task_hits = hits.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            task_hits.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = vec![0_u8; 8192];
                let _ = timeout(Duration::from_secs(5), stream.read(&mut buffer)).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, hits, task)
}

fn free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

fn test_directory() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("live-listener")
        .join(format!("{}-{stamp}", std::process::id()))
}

async fn wait_for_tcp(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("native server did not start listening on {address}");
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn client_roots(certificate: &CertificateDer<'static>) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    roots
}

fn proxy_v2_v4_header(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let (std::net::IpAddr::V4(source_ip), std::net::IpAddr::V4(destination_ip)) =
        (source.ip(), destination.ip())
    else {
        panic!("test helper only supports IPv4");
    };
    let mut frame = Vec::new();
    frame.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    frame.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
    frame.extend_from_slice(&source_ip.octets());
    frame.extend_from_slice(&destination_ip.octets());
    frame.extend_from_slice(&source.port().to_be_bytes());
    frame.extend_from_slice(&destination.port().to_be_bytes());
    frame
}

struct ClientIdentity {
    certificate: CertificateDer<'static>,
    key_pem: String,
    ca_pem: String,
    crl_der: Vec<u8>,
}

fn make_client_identity(revoked: bool) -> ClientIdentity {
    const CLIENT_SERIAL: u64 = 0x55aa;

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "HighWall test client CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_certificate.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let mut client_params = CertificateParams::new(vec!["client.test".to_string()]).unwrap();
    client_params.serial_number = Some(SerialNumber::from(CLIENT_SERIAL));
    client_params.use_authority_key_identifier_extension = true;
    client_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let client_key = KeyPair::generate().unwrap();
    let client_certificate = client_params.signed_by(&client_key, &issuer).unwrap();

    let revoked_certs = if revoked {
        vec![RevokedCertParams {
            serial_number: SerialNumber::from(CLIENT_SERIAL),
            revocation_time: rcgen::date_time_ymd(2026, 1, 1),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }]
    } else {
        Vec::new()
    };
    let crl = CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2025, 1, 1),
        next_update: rcgen::date_time_ymd(2035, 1, 1),
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&issuer)
    .unwrap()
    .der()
    .to_vec();

    ClientIdentity {
        certificate: client_certificate.der().clone(),
        key_pem: client_key.serialize_pem(),
        ca_pem,
        crl_der: crl,
    }
}

fn mtls_client_config(
    server_certificate: &CertificateDer<'static>,
    identity: &ClientIdentity,
) -> rustls::ClientConfig {
    let mut key_reader = std::io::BufReader::new(identity.key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .unwrap()
        .expect("client key must parse");
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(client_roots(server_certificate))
    .with_client_auth_cert(vec![identity.certificate.clone()], key)
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

async fn wait_for_audit_text(path: &Path, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.contains(needle) {
            return;
        }
        if Instant::now() >= deadline {
            panic!("audit file never contained {needle:?}: {text}");
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn assert_rejected_without_data(stream: &mut TcpStream, context: &str) {
    let mut byte = [0_u8; 1];
    match timeout(Duration::from_secs(2), stream.read(&mut byte))
        .await
        .expect(context)
    {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) => {}
        Ok(read) => panic!("{context}: received {read} byte(s) instead of a close"),
        Err(error) => panic!("{context}: unexpected read error: {error}"),
    }
}

async fn read_h2_response(mut body: h2::RecvStream) -> Vec<u8> {
    let mut received = Vec::new();
    while let Some(Ok(chunk)) = timeout(Duration::from_secs(5), body.data()).await.unwrap() {
        received.extend_from_slice(&chunk);
    }
    received
}

async fn connect_h2(server: &LiveServer) -> (h2::client::SendRequest<Bytes>, JoinHandle<()>) {
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(client_roots(&server.certificate))
    .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(crypto));
    let tcp = TcpStream::connect(server.tcp).await.unwrap();
    let tls = timeout(
        Duration::from_secs(5),
        connector.connect(
            rustls::pki_types::ServerName::try_from("localhost")
                .unwrap()
                .to_owned(),
            tcp,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let (client, connection) = timeout(Duration::from_secs(5), h2::client::handshake(tls))
        .await
        .unwrap()
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (client, driver)
}

async fn send_h2_get(
    client: &mut h2::client::SendRequest<Bytes>,
    path: &str,
) -> (http::StatusCode, http::HeaderMap, Vec<u8>) {
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://localhost{path}"))
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, send_stream) = client.send_request(request, true).unwrap();
    drop(send_stream);
    let response = timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = read_h2_response(response.into_body()).await;
    (status, headers, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_tcp_tls_h2_listener_reaches_upstream() {
    let server = start_server().await;
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(client_roots(&server.certificate))
    .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(crypto));
    let tcp = TcpStream::connect(server.tcp).await.unwrap();
    let tls = timeout(
        Duration::from_secs(5),
        connector.connect(
            rustls::pki_types::ServerName::try_from("localhost")
                .unwrap()
                .to_owned(),
            tcp,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut client, connection) = timeout(Duration::from_secs(5), h2::client::handshake(tls))
        .await
        .unwrap()
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
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
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = read_h2_response(response.into_body()).await;
    assert_eq!(body, b"ok");
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_tcp_listener_survives_connection_churn() {
    let server = start_server_with_options(
        ProxyProtocolConfig::default(),
        None,
        None,
        Vec::new(),
        |config| {
            config.limits.max_connections_per_ip = 512;
            config.limits.max_tls_handshakes_per_second_per_ip = 10_000.0;
            config.limits.max_tls_handshake_burst_per_ip = 20_000.0;
        },
    )
    .await;

    for _ in 0..128 {
        let stream = timeout(Duration::from_secs(2), TcpStream::connect(server.tcp))
            .await
            .expect("connection churn attempt timed out")
            .expect("listener stopped accepting during connection churn");
        drop(stream);
    }
    sleep(Duration::from_millis(100)).await;

    let (mut client, driver) = connect_h2(&server).await;
    let (status, _headers, body) = send_h2_get(&mut client, "/ok").await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(body, b"ok");
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 1);
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_ban_remains_observable_after_tls_handshake() {
    let server = start_server_with_options(
        ProxyProtocolConfig::default(),
        None,
        None,
        Vec::new(),
        |config| {
            config.bans.enabled = true;
            config.bans.ttl_seconds = 60;
            config.bans.max_ttl_seconds = 60;
            config.bans.violation_threshold = 2;
            config.bans.violation_window_seconds = 60;
        },
    )
    .await;
    let (mut client, driver) = connect_h2(&server).await;
    for _ in 0..2 {
        let (status, _headers, body) = send_h2_get(&mut client, "/.git/HEAD").await;
        assert_eq!(status, http::StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&body).contains("HW-NATIVE-WAF-006"));
    }
    driver.abort();

    let (mut banned_client, banned_driver) = connect_h2(&server).await;
    let (status, headers, body) = send_h2_get(&mut banned_client, "/ok").await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&body).contains("HW-NATIVE-BAN-001"));
    let retry_after = headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("banned response must expose Retry-After");
    assert!(retry_after > 0 && retry_after <= 60);
    assert_eq!(
        headers
            .get("x-ratelimit-policy")
            .and_then(|value| value.to_str().ok()),
        Some("highwall-source-ban")
    );
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 0);
    banned_driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_h3_ban_remains_observable_after_quic_handshake() {
    let server = start_server_with_options(
        ProxyProtocolConfig::default(),
        None,
        None,
        Vec::new(),
        |config| {
            config.bans.enabled = true;
            config.bans.ttl_seconds = 60;
            config.bans.max_ttl_seconds = 60;
            config.bans.violation_threshold = 2;
            config.bans.violation_window_seconds = 60;
        },
    )
    .await;
    let endpoint = quic_client_endpoint(&server.certificate, b"h3", false);
    let connection = timeout(
        Duration::from_secs(10),
        endpoint.connect(server.quic, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut driver, mut send_request) = timeout(
        Duration::from_secs(5),
        h3::client::new(h3_quinn::Connection::new(connection)),
    )
    .await
    .unwrap()
    .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    for _ in 0..2 {
        let (status, _headers, _body) =
            send_h3_request_with_headers(&mut send_request, "/.git/HEAD").await;
        assert_eq!(status, http::StatusCode::FORBIDDEN);
    }

    let banned_connection = timeout(
        Duration::from_secs(10),
        endpoint.connect(server.quic, "localhost").unwrap(),
    )
    .await
    .expect("a banned source must still complete the QUIC handshake")
    .expect("a banned source must not be dropped before QUIC negotiation");
    let (mut banned_driver, mut banned_requests) = timeout(
        Duration::from_secs(5),
        h3::client::new(h3_quinn::Connection::new(banned_connection)),
    )
    .await
    .unwrap()
    .unwrap();
    let banned_driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| banned_driver.poll_close(cx)).await;
    });
    let (status, headers, body) = send_h3_request_with_headers(&mut banned_requests, "/ok").await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert_eq!(
        headers
            .get("x-ratelimit-policy")
            .and_then(|value| value.to_str().ok()),
        Some("highwall-source-ban")
    );
    assert!(headers.get("retry-after").is_some());
    assert!(
        String::from_utf8_lossy(&body).contains("HW-NATIVE-BAN-001"),
        "ban response must expose a stable rule id"
    );
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 0);
    endpoint.close(quinn::VarInt::from_u32(0), b"ban test complete");
    driver_task.abort();
    banned_driver_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_proxy_v2_source_reaches_tls_h2_and_is_audited() {
    let server = start_server_with_proxy(ProxyProtocolConfig {
        mode: ProxyProtocolMode::Required,
        trusted_proxy_networks: vec!["127.0.0.1/32".parse().unwrap()],
        header_timeout_ms: 1_000,
    })
    .await;
    let forwarded = "203.0.113.50:51234".parse().unwrap();
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(client_roots(&server.certificate))
    .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(crypto));

    let mut tcp = TcpStream::connect(server.tcp).await.unwrap();
    tcp.write_all(&proxy_v2_v4_header(forwarded, server.tcp))
        .await
        .unwrap();
    let tls = timeout(
        Duration::from_secs(5),
        connector.connect(
            rustls::pki_types::ServerName::try_from("localhost")
                .unwrap()
                .to_owned(),
            tcp,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut client, connection) = timeout(Duration::from_secs(5), h2::client::handshake(tls))
        .await
        .unwrap()
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
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
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(read_h2_response(response.into_body()).await, b"ok");
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 1);
    wait_for_audit_text(&server.audit_path, r#""peer":"203.0.113.50:51234""#).await;
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_required_proxy_v2_rejects_missing_header() {
    let server = start_server_with_proxy(ProxyProtocolConfig {
        mode: ProxyProtocolMode::Required,
        trusted_proxy_networks: vec!["127.0.0.1/32".parse().unwrap()],
        header_timeout_ms: 500,
    })
    .await;

    let mut tcp = TcpStream::connect(server.tcp).await.unwrap();
    tcp.write_all(&[0x16]).await.unwrap();
    assert_rejected_without_data(&mut tcp, "server accepted a connection without PROXY v2").await;
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_untrusted_peer_cannot_forge_proxy_v2_source() {
    let server = start_server_with_proxy(ProxyProtocolConfig {
        mode: ProxyProtocolMode::Required,
        trusted_proxy_networks: vec!["203.0.113.9/32".parse().unwrap()],
        header_timeout_ms: 500,
    })
    .await;

    let mut tcp = TcpStream::connect(server.tcp).await.unwrap();
    let forged_source = "198.51.100.77:40000".parse().unwrap();
    let _ = tcp
        .write_all(&proxy_v2_v4_header(forged_source, server.tcp))
        .await;
    assert_rejected_without_data(
        &mut tcp,
        "untrusted peer was allowed to inject a source address",
    )
    .await;
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_mtls_client_certificate_with_valid_crl_reaches_upstream() {
    let identity = make_client_identity(false);
    let server = start_server_with_mtls(identity.ca_pem.clone(), identity.crl_der.clone()).await;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(mtls_client_config(
        &server.certificate,
        &identity,
    )));
    let tcp = TcpStream::connect(server.tcp).await.unwrap();
    let tls = timeout(
        Duration::from_secs(5),
        connector.connect(
            rustls::pki_types::ServerName::try_from("localhost")
                .unwrap()
                .to_owned(),
            tcp,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut client, connection) = timeout(Duration::from_secs(5), h2::client::handshake(tls))
        .await
        .unwrap()
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
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
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(read_h2_response(response.into_body()).await, b"ok");
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 1);
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_mtls_revoked_client_certificate_fails_before_upstream() {
    let identity = make_client_identity(true);
    let server = start_server_with_mtls(identity.ca_pem.clone(), identity.crl_der.clone()).await;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(mtls_client_config(
        &server.certificate,
        &identity,
    )));
    let tcp = TcpStream::connect(server.tcp).await.unwrap();
    let tls_result = timeout(
        Duration::from_secs(5),
        connector.connect(
            rustls::pki_types::ServerName::try_from("localhost")
                .unwrap()
                .to_owned(),
            tcp,
        ),
    )
    .await
    .expect("revoked client certificate attempt timed out");
    if let Ok(tls) = tls_result {
        if let Ok(Ok((mut client, connection))) =
            timeout(Duration::from_secs(3), h2::client::handshake(tls)).await
        {
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let request = http::Request::builder()
                .method("GET")
                .uri("https://localhost/ok")
                .header("host", "localhost")
                .body(())
                .unwrap();
            if let Ok((response, send_stream)) = client.send_request(request, true) {
                drop(send_stream);
                if let Ok(Ok(response)) = timeout(Duration::from_secs(2), response).await {
                    panic!(
                        "revoked client certificate received an HTTP response: {}",
                        response.status()
                    );
                }
            }
            driver.abort();
        }
    }
    wait_for_audit_text(&server.audit_path, "HW-NATIVE-TLS-001").await;
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_quic_h3_binds_separate_host_and_reaches_upstream() {
    let quic_host = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let server = start_server_with_quic_host(quic_host).await;
    assert_eq!(server.quic.ip(), quic_host);
    let endpoint = quic_client_endpoint(&server.certificate, b"h3", false);
    let connection = timeout(
        Duration::from_secs(10),
        endpoint.connect(server.quic, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut driver, mut send_request) = timeout(
        Duration::from_secs(5),
        h3::client::new(h3_quinn::Connection::new(connection)),
    )
    .await
    .unwrap()
    .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let response = send_h3_request(&mut send_request, "/ok").await;
    assert_eq!(response.0, http::StatusCode::OK);
    assert_eq!(response.1, b"ok");
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 1);
    endpoint.close(quinn::VarInt::from_u32(0), b"test complete");
    driver_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_quic_unlisted_peer_is_ignored_before_retry() {
    let server = start_server_with_quic_acl(vec!["203.0.113.10/32".parse().unwrap()]).await;
    let endpoint = quic_client_endpoint(&server.certificate, b"h3", false);
    let result = timeout(
        Duration::from_secs(2),
        endpoint.connect(server.quic, "localhost").unwrap(),
    )
    .await;
    assert!(
        result.is_err() || matches!(result, Ok(Err(_))),
        "QUIC accepted a peer outside the client allowlist"
    );
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 0);
    wait_for_audit_text(&server.audit_path, "HW-NATIVE-QUIC-ACL-001").await;
    endpoint.close(quinn::VarInt::from_u32(0), b"allowlist test complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_quic_allowed_peer_reaches_h3() {
    let server = start_server_with_quic_acl(vec!["127.0.0.1/32".parse().unwrap()]).await;
    let endpoint = quic_client_endpoint(&server.certificate, b"h3", false);
    let connection = timeout(
        Duration::from_secs(10),
        endpoint.connect(server.quic, "localhost").unwrap(),
    )
    .await
    .expect("an allowlisted local peer must not be filtered before Retry")
    .expect("an allowlisted local peer must complete the QUIC handshake");
    let (mut driver, mut send_request) = timeout(
        Duration::from_secs(5),
        h3::client::new(h3_quinn::Connection::new(connection)),
    )
    .await
    .unwrap()
    .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let response = send_h3_request(&mut send_request, "/ok").await;
    assert_eq!(response.0, http::StatusCode::OK);
    assert_eq!(response.1, b"ok");
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 1);
    endpoint.close(quinn::VarInt::from_u32(0), b"allowlist test complete");
    driver_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_quic_unknown_alpn_is_rejected_without_upstream() {
    let server = start_server().await;
    let endpoint = quic_client_endpoint(&server.certificate, b"http/1.1", false);
    let result = timeout(
        Duration::from_secs(10),
        endpoint.connect(server.quic, "localhost").unwrap(),
    )
    .await
    .expect("unknown ALPN must fail during the handshake, not hang");
    assert!(result.is_err(), "unknown ALPN negotiated a connection");
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 0);
    endpoint.close(quinn::VarInt::from_u32(0), b"unknown ALPN rejected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_quic_sends_retry_before_h3() {
    let server = start_server().await;
    let (proxy, retry_seen, proxy_task) = spawn_retry_observing_proxy(server.quic).await;
    let endpoint = quic_client_endpoint(&server.certificate, b"h3", false);
    let connection = timeout(
        Duration::from_secs(10),
        endpoint.connect(proxy, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        retry_seen.load(Ordering::SeqCst),
        "QUIC server did not send a Retry packet"
    );
    let (mut driver, mut send_request) = timeout(
        Duration::from_secs(5),
        h3::client::new(h3_quinn::Connection::new(connection)),
    )
    .await
    .unwrap()
    .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let response = send_h3_request(&mut send_request, "/ok").await;
    assert_eq!(response.0, http::StatusCode::OK);
    assert_eq!(response.1, b"ok");
    endpoint.close(quinn::VarInt::from_u32(0), b"retry test complete");
    driver_task.abort();
    proxy_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_quic_disables_zero_rtt_for_resumed_sessions() {
    let server = start_server().await;
    let endpoint = quic_client_endpoint(&server.certificate, b"h3", true);
    let connection = timeout(
        Duration::from_secs(10),
        endpoint.connect(server.quic, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut driver, mut send_request) = timeout(
        Duration::from_secs(5),
        h3::client::new(h3_quinn::Connection::new(connection)),
    )
    .await
    .unwrap()
    .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let response = send_h3_request(&mut send_request, "/ok").await;
    assert_eq!(response.0, http::StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(send_request);
    driver_task.abort();

    let resumed = endpoint.connect(server.quic, "localhost").unwrap();
    assert!(
        resumed.into_0rtt().is_err(),
        "0-RTT must not be available when the server advertises no early data"
    );
    endpoint.close(quinn::VarInt::from_u32(0), b"0-RTT rejected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_quic_connection_migration_is_rejected() {
    let server = start_server().await;
    let endpoint = quic_client_endpoint(&server.certificate, b"h3", false);
    let connection = timeout(
        Duration::from_secs(10),
        endpoint.connect(server.quic, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut driver, mut send_request) = timeout(
        Duration::from_secs(5),
        h3::client::new(h3_quinn::Connection::new(connection)),
    )
    .await
    .unwrap()
    .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let first = send_h3_request(&mut send_request, "/ok").await;
    assert_eq!(first.0, http::StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let migrated_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    endpoint.rebind(migrated_socket).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let request = http::Request::get("https://localhost/ok").body(()).unwrap();
    let result = timeout(Duration::from_secs(3), async {
        let mut stream = send_request.send_request(request).await?;
        stream.finish().await?;
        stream.recv_response().await
    })
    .await;
    assert!(
        result.is_err() || matches!(result, Ok(Err(_))),
        "server accepted an active connection migration"
    );
    assert_eq!(server.upstream_hits.load(Ordering::SeqCst), 1);
    endpoint.close(quinn::VarInt::from_u32(0), b"migration rejected");
    driver_task.abort();
}

fn quic_client_endpoint(
    certificate: &CertificateDer<'static>,
    alpn: &[u8],
    enable_early_data: bool,
) -> quinn::Endpoint {
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(client_roots(certificate))
    .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.to_vec()];
    crypto.enable_early_data = enable_early_data;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

async fn send_h3_request(
    send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    path: &str,
) -> (http::StatusCode, Vec<u8>) {
    let request = http::Request::get(format!("https://localhost{path}"))
        .body(())
        .unwrap();
    let mut stream = timeout(Duration::from_secs(5), send_request.send_request(request))
        .await
        .unwrap()
        .unwrap();
    stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(5), stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    let mut body = Vec::new();
    while let Some(chunk) = timeout(Duration::from_secs(5), stream.recv_data())
        .await
        .unwrap()
        .unwrap()
    {
        body.extend_from_slice(chunk.chunk());
    }
    (status, body)
}

async fn send_h3_request_with_headers(
    send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    path: &str,
) -> (http::StatusCode, http::HeaderMap, Vec<u8>) {
    let request = http::Request::get(format!("https://localhost{path}"))
        .body(())
        .unwrap();
    let mut stream = timeout(Duration::from_secs(5), send_request.send_request(request))
        .await
        .unwrap()
        .unwrap();
    stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(5), stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let mut body = Vec::new();
    while let Some(chunk) = timeout(Duration::from_secs(5), stream.recv_data())
        .await
        .unwrap()
        .unwrap()
    {
        body.extend_from_slice(chunk.chunk());
    }
    (status, headers, body)
}

async fn spawn_retry_observing_proxy(
    server: SocketAddr,
) -> (SocketAddr, Arc<AtomicBool>, JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let retry_seen = Arc::new(AtomicBool::new(false));
    let task_flag = retry_seen.clone();
    let task = tokio::spawn(async move {
        let mut client = None;
        let mut buffer = vec![0_u8; 4096];
        loop {
            let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            if source == server {
                if length > 0 && buffer[0] & 0xf0 == 0xf0 {
                    task_flag.store(true, Ordering::SeqCst);
                }
                if let Some(client) = client {
                    let _ = socket.send_to(&buffer[..length], client).await;
                }
            } else {
                client = Some(source);
                let _ = socket.send_to(&buffer[..length], server).await;
            }
        }
    });
    (address, retry_seen, task)
}
