use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppConfig {
    pub listen: ListenConfig,
    pub tls: Option<TlsConfig>,
    pub quic: Option<QuicConfig>,
    pub upstream: UpstreamConfig,
    pub limits: LimitsConfig,
    pub audit: AuditConfig,
    pub policy: PolicyConfig,
    pub routes: Vec<RouteConfig>,
    pub agent: AgentConfig,
    pub bans: BanConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen: ListenConfig::default(),
            tls: None,
            quic: None,
            upstream: UpstreamConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig::default(),
            policy: PolicyConfig::default(),
            routes: vec![RouteConfig::default()],
            agent: AgentConfig::default(),
            bans: BanConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListenConfig {
    pub host: IpAddr,
    pub port: u16,
    pub allow_non_loopback: bool,
    pub proxy_protocol: ProxyProtocolConfig,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 18080,
            allow_non_loopback: false,
            proxy_protocol: ProxyProtocolConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyProtocolConfig {
    pub mode: ProxyProtocolMode,
    pub trusted_proxy_networks: Vec<IpNet>,
    pub header_timeout_ms: u64,
}

impl Default for ProxyProtocolConfig {
    fn default() -> Self {
        Self {
            mode: ProxyProtocolMode::Off,
            trusted_proxy_networks: Vec::new(),
            header_timeout_ms: 2_000,
        }
    }
}

impl ProxyProtocolConfig {
    pub fn trusts(&self, address: IpAddr) -> bool {
        self.trusted_proxy_networks
            .iter()
            .any(|network| network.contains(&address))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocolMode {
    Off,
    Optional,
    Required,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub crl_file: Option<PathBuf>,
    pub require_private_key_permissions: bool,
    pub min_version: TlsMinVersion,
    pub validate_certificate: bool,
    pub allowed_sni: Vec<String>,
    pub allow_missing_sni: bool,
    pub mtls: MtlsMode,
    pub client_ca_file: Option<PathBuf>,
    pub client_crl_file: Option<PathBuf>,
    pub alpn: Vec<String>,
    pub require_sni_host_match: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_file: PathBuf::from("cert.pem"),
            key_file: PathBuf::from("key.pem"),
            crl_file: None,
            require_private_key_permissions: true,
            min_version: TlsMinVersion::Tls13,
            validate_certificate: true,
            allowed_sni: vec!["localhost".to_string()],
            allow_missing_sni: false,
            mtls: MtlsMode::Off,
            client_ca_file: None,
            client_crl_file: None,
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            require_sni_host_match: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMinVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MtlsMode {
    Off,
    Optional,
    Required,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuicConfig {
    pub enabled: bool,
    pub host: Option<IpAddr>,
    pub listen_port: u16,
    pub allowed_client_networks: Vec<IpNet>,
    pub max_concurrent_bidi_streams: u32,
    pub max_concurrent_uni_streams: u32,
    pub max_idle_timeout_ms: u64,
    pub max_udp_payload_size: u16,
    pub require_retry: bool,
    pub allow_migration: bool,
    pub max_inflight_handshakes: usize,
    pub handshake_timeout_ms: u64,
    pub stream_receive_window_bytes: u64,
    pub connection_receive_window_bytes: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: None,
            listen_port: 18443,
            allowed_client_networks: Vec::new(),
            max_concurrent_bidi_streams: 64,
            max_concurrent_uni_streams: 16,
            max_idle_timeout_ms: 30_000,
            max_udp_payload_size: 1350,
            require_retry: true,
            allow_migration: false,
            max_inflight_handshakes: 128,
            handshake_timeout_ms: 5_000,
            stream_receive_window_bytes: 1024 * 1024,
            connection_receive_window_bytes: 16 * 1024 * 1024,
        }
    }
}

impl QuicConfig {
    pub fn effective_host(&self, listen: &ListenConfig) -> IpAddr {
        self.host.unwrap_or(listen.host)
    }

    pub fn allows(&self, address: IpAddr) -> bool {
        self.allowed_client_networks.is_empty()
            || self
                .allowed_client_networks
                .iter()
                .any(|network| network.contains(&address))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    pub host: String,
    pub port: u16,
    pub h2_for_grpc: bool,
    pub set_forwarded_for: bool,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 18081,
            h2_for_grpc: true,
            set_forwarded_for: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub max_requests_per_connection: usize,
    pub max_head_bytes: usize,
    pub max_header_count: usize,
    pub max_header_line_bytes: usize,
    pub max_body_bytes: usize,
    pub max_response_bytes: usize,
    pub header_timeout_ms: u64,
    pub body_idle_timeout_ms: u64,
    pub request_total_timeout_ms: u64,
    pub upstream_connect_timeout_ms: u64,
    pub upstream_read_timeout_ms: u64,
    pub max_h2_streams: u32,
    pub max_h2_stream_window_bytes: u32,
    pub max_h2_connection_window_bytes: u32,
    pub max_h2_requests_per_connection: usize,
    pub max_h2_reset_errors: usize,
    pub max_h2_pings_per_second: f64,
    pub max_h2_ping_burst: f64,
    pub max_h2_ping_frames_per_connection: usize,
    pub max_h2_header_list_bytes: usize,
    pub max_h2_frame_size: u32,
    pub max_h2_send_buffer_bytes: usize,
    pub h2_idle_timeout_ms: u64,
    pub max_h3_streams: u32,
    pub max_h3_requests_per_connection: usize,
    pub max_h3_reset_errors: usize,
    pub max_h3_field_section_bytes: u64,
    pub max_ws_frame_bytes: usize,
    pub max_ws_message_bytes: usize,
    pub max_ws_messages_per_second: usize,
    pub max_ws_idle_timeout_ms: u64,
    pub max_grpc_message_bytes: usize,
    pub max_grpc_messages: usize,
    pub max_grpc_total_bytes: usize,
    pub max_inspect_decoded_bytes: usize,
    pub tls_handshake_timeout_ms: u64,
    pub max_tls_handshakes_per_second_per_ip: f64,
    pub max_tls_handshake_burst_per_ip: f64,
    pub max_tls_handshake_entries: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_connections_per_ip: 64,
            max_requests_per_connection: 100,
            max_head_bytes: 32 * 1024,
            max_header_count: 100,
            max_header_line_bytes: 8 * 1024,
            max_body_bytes: 8 * 1024 * 1024,
            max_response_bytes: 16 * 1024 * 1024,
            header_timeout_ms: 5_000,
            body_idle_timeout_ms: 15_000,
            request_total_timeout_ms: 30_000,
            upstream_connect_timeout_ms: 3_000,
            upstream_read_timeout_ms: 15_000,
            max_h2_streams: 64,
            max_h2_stream_window_bytes: 1024 * 1024,
            max_h2_connection_window_bytes: 16 * 1024 * 1024,
            max_h2_requests_per_connection: 2_000,
            max_h2_reset_errors: 32,
            max_h2_pings_per_second: 10.0,
            max_h2_ping_burst: 20.0,
            max_h2_ping_frames_per_connection: 1_000,
            max_h2_header_list_bytes: 32 * 1024,
            max_h2_frame_size: 16_384,
            max_h2_send_buffer_bytes: 1024 * 1024,
            h2_idle_timeout_ms: 60_000,
            max_h3_streams: 64,
            max_h3_requests_per_connection: 2_000,
            max_h3_reset_errors: 32,
            max_h3_field_section_bytes: 32 * 1024,
            max_ws_frame_bytes: 256 * 1024,
            max_ws_message_bytes: 1024 * 1024,
            max_ws_messages_per_second: 100,
            max_ws_idle_timeout_ms: 120_000,
            max_grpc_message_bytes: 4 * 1024 * 1024,
            max_grpc_messages: 1024,
            max_grpc_total_bytes: 16 * 1024 * 1024,
            max_inspect_decoded_bytes: 16 * 1024 * 1024,
            tls_handshake_timeout_ms: 5_000,
            max_tls_handshakes_per_second_per_ip: 20.0,
            max_tls_handshake_burst_per_ip: 40.0,
            max_tls_handshake_entries: 65_536,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    pub enabled: bool,
    pub path: PathBuf,
    pub queue_capacity: usize,
    pub fail_closed: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: PathBuf::from("native-audit.jsonl"),
            queue_capacity: 4096,
            fail_closed: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub require_host: bool,
    pub allowed_methods: Vec<String>,
    pub max_path_bytes: usize,
    pub max_query_bytes: usize,
    pub inspect_compressed_bodies: bool,
    pub rate_limit: RateLimitConfig,
    pub waf: WafConfig,
    pub dlp: DlpConfig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            require_host: true,
            allowed_methods: vec![
                "GET".to_string(),
                "HEAD".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            max_path_bytes: 4096,
            max_query_bytes: 8192,
            inspect_compressed_bodies: true,
            rate_limit: RateLimitConfig::default(),
            waf: WafConfig::default(),
            dlp: DlpConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    pub requests_per_second: f64,
    pub burst: f64,
    pub max_entries: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 500.0,
            burst: 1_000.0,
            max_entries: 65_536,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WafConfig {
    pub enabled: bool,
    pub deny_scanner_paths: bool,
    pub inspect_query: bool,
    pub inspect_headers: bool,
    pub inspect_body_text: bool,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deny_scanner_paths: true,
            inspect_query: true,
            inspect_headers: true,
            inspect_body_text: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DlpConfig {
    pub enabled: bool,
    pub inspect_request: bool,
    pub inspect_response: bool,
    pub detect_high_entropy: bool,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            inspect_request: true,
            inspect_response: true,
            detect_high_entropy: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteConfig {
    pub name: String,
    pub host: Option<String>,
    pub path_prefix: String,
    pub methods: Vec<String>,
    pub upstream: Option<UpstreamConfig>,
    pub websocket: bool,
    pub ws_origins: Vec<String>,
    pub ws_subprotocols: Vec<String>,
    pub ws_require_origin: bool,
    pub ws_allow_same_origin: bool,
    pub ws_require_subprotocol: bool,
    pub ws_allow_extensions: bool,
    pub ws_inspect_messages: bool,
    pub grpc: bool,
    pub waf: bool,
    pub dlp: bool,
    pub audit: bool,
    pub max_body_bytes: Option<usize>,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            host: None,
            path_prefix: "/".to_string(),
            methods: Vec::new(),
            upstream: None,
            websocket: false,
            ws_origins: Vec::new(),
            ws_subprotocols: Vec::new(),
            ws_require_origin: true,
            ws_allow_same_origin: false,
            ws_require_subprotocol: false,
            ws_allow_extensions: false,
            ws_inspect_messages: true,
            grpc: false,
            waf: true,
            dlp: true,
            audit: true,
            max_body_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub enabled: bool,
    pub mode: AgentMode,
    pub max_entries: usize,
    pub window_seconds: u64,
    pub max_requests_per_window: usize,
    pub max_distinct_paths: usize,
    pub max_distinct_methods: usize,
    pub max_user_agent_changes: usize,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: AgentMode::Suspect,
            max_entries: 16_384,
            window_seconds: 60,
            max_requests_per_window: 600,
            max_distinct_paths: 120,
            max_distinct_methods: 8,
            max_user_agent_changes: 12,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    Observe,
    Suspect,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BanConfig {
    pub enabled: bool,
    pub ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub max_entries: usize,
    pub violation_threshold: usize,
    pub violation_window_seconds: u64,
    pub response_violation_threshold: usize,
    pub response_violation_window_seconds: u64,
}

impl Default for BanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_seconds: 300,
            max_ttl_seconds: 900,
            max_entries: 4096,
            violation_threshold: 500,
            violation_window_seconds: 60,
            response_violation_threshold: 500,
            response_violation_window_seconds: 300,
        }
    }
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|error| {
            CoreError::Config(format!("cannot read {}: {error}", path.display()))
        })?;
        let mut config: Self = serde_json::from_str(&raw)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if let Some(tls) = config.tls.as_mut() {
            tls.cert_file = resolve_existing(base, &tls.cert_file, "tls.cert_file")?;
            tls.key_file = resolve_existing(base, &tls.key_file, "tls.key_file")?;
            if let Some(crl) = tls.crl_file.as_mut() {
                *crl = resolve_existing(base, crl, "tls.crl_file")?;
            }
            if let Some(ca) = tls.client_ca_file.as_mut() {
                *ca = resolve_existing(base, ca, "tls.client_ca_file")?;
            }
            if let Some(crl) = tls.client_crl_file.as_mut() {
                *crl = resolve_existing(base, crl, "tls.client_crl_file")?;
            }
        }
        if config.audit.enabled {
            config.audit.path = resolve_for_output(base, &config.audit.path, "audit.path")?;
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.listen.allow_non_loopback && !self.listen.host.is_loopback() {
            return Err(CoreError::Config(
                "listen.host must be loopback unless allow_non_loopback is true".to_string(),
            ));
        }
        if self.listen.port == 0 && self.listen.host.is_unspecified() {
            return Err(CoreError::Config(
                "unspecified listen address is not allowed".to_string(),
            ));
        }
        validate_proxy_protocol(&self.listen.proxy_protocol)?;
        if self.routes.is_empty() {
            return Err(CoreError::Config(
                "at least one explicit route is required".to_string(),
            ));
        }
        if self.limits.max_connections == 0
            || self.limits.max_connections_per_ip == 0
            || self.limits.max_head_bytes < 1024
            || self.limits.max_header_count == 0
            || self.limits.max_body_bytes == 0
            || self.limits.max_response_bytes == 0
            || self.limits.max_h2_streams == 0
            || self.limits.max_h2_stream_window_bytes == 0
            || self.limits.max_h2_connection_window_bytes == 0
            || self.limits.max_h2_requests_per_connection == 0
            || self.limits.max_h2_ping_frames_per_connection == 0
            || !self.limits.max_h2_pings_per_second.is_finite()
            || self.limits.max_h2_pings_per_second <= 0.0
            || !self.limits.max_h2_ping_burst.is_finite()
            || self.limits.max_h2_ping_burst < 1.0
            || self.limits.max_h2_header_list_bytes < 1024
            || !(16_384..=16_777_215).contains(&self.limits.max_h2_frame_size)
            || self.limits.max_h2_send_buffer_bytes < 16_384
            || self.limits.h2_idle_timeout_ms == 0
            || self.limits.max_h3_streams == 0
            || self.limits.max_h3_requests_per_connection == 0
            || self.limits.max_h3_reset_errors == 0
            || self.limits.max_h3_field_section_bytes == 0
            || self.limits.max_ws_frame_bytes == 0
            || self.limits.max_ws_message_bytes == 0
            || self.limits.max_ws_messages_per_second == 0
            || self.limits.max_ws_idle_timeout_ms == 0
            || self.limits.max_grpc_message_bytes == 0
            || self.limits.max_grpc_messages == 0
            || self.limits.max_grpc_total_bytes == 0
            || self.limits.max_inspect_decoded_bytes == 0
            || self.limits.tls_handshake_timeout_ms == 0
            || !self.limits.max_tls_handshakes_per_second_per_ip.is_finite()
            || self.limits.max_tls_handshakes_per_second_per_ip <= 0.0
            || !self.limits.max_tls_handshake_burst_per_ip.is_finite()
            || self.limits.max_tls_handshake_burst_per_ip < 1.0
            || self.limits.max_tls_handshake_entries == 0
        {
            return Err(CoreError::Config(
                "resource limits must be positive and non-trivial".to_string(),
            ));
        }
        if self.limits.max_ws_frame_bytes > self.limits.max_ws_message_bytes {
            return Err(CoreError::Config(
                "max_ws_frame_bytes cannot exceed max_ws_message_bytes".to_string(),
            ));
        }
        if self.limits.max_grpc_message_bytes > self.limits.max_grpc_total_bytes {
            return Err(CoreError::Config(
                "max_grpc_message_bytes cannot exceed max_grpc_total_bytes".to_string(),
            ));
        }
        if self.limits.max_connections_per_ip > self.limits.max_connections {
            return Err(CoreError::Config(
                "max_connections_per_ip cannot exceed max_connections".to_string(),
            ));
        }
        if self.limits.max_h2_stream_window_bytes > self.limits.max_h2_connection_window_bytes
            || self.limits.max_h2_connection_window_bytes > i32::MAX as u32
        {
            return Err(CoreError::Config(
                "HTTP/2 window sizes must be ordered and at most 2^31-1".to_string(),
            ));
        }
        if self.audit.enabled && self.audit.queue_capacity == 0 {
            return Err(CoreError::Config(
                "audit.queue_capacity must be positive".to_string(),
            ));
        }
        if let Some(tls) = &self.tls {
            ensure_regular_file(&tls.cert_file, "tls.cert_file")?;
            ensure_regular_file(&tls.key_file, "tls.key_file")?;
            if let Some(crl) = &tls.crl_file {
                ensure_regular_file(crl, "tls.crl_file")?;
            }
            if let Some(ca) = &tls.client_ca_file {
                ensure_regular_file(ca, "tls.client_ca_file")?;
            }
            if let Some(crl) = &tls.client_crl_file {
                ensure_regular_file(crl, "tls.client_crl_file")?;
            }
            if tls.allowed_sni.is_empty() {
                return Err(CoreError::Config(
                    "tls.allowed_sni cannot be empty".to_string(),
                ));
            }
            if tls.alpn.is_empty() || tls.alpn.iter().any(|value| value.is_empty()) {
                return Err(CoreError::Config(
                    "tls.alpn must contain non-empty values".to_string(),
                ));
            }
            if tls
                .alpn
                .iter()
                .any(|value| !matches!(value.as_str(), "h2" | "http/1.1"))
            {
                return Err(CoreError::Config(
                    "tls.alpn may only contain h2 and http/1.1 for the TCP listener".to_string(),
                ));
            }
            if tls
                .alpn
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != tls.alpn.len()
            {
                return Err(CoreError::Config(
                    "tls.alpn contains duplicates".to_string(),
                ));
            }
            if !tls.alpn.iter().any(|value| value == "http/1.1")
                && !tls.alpn.iter().any(|value| value == "h2")
            {
                return Err(CoreError::Config(
                    "tls.alpn must include h2 or http/1.1 for TCP service".to_string(),
                ));
            }
            if tls.mtls != MtlsMode::Off && tls.client_ca_file.is_none() {
                return Err(CoreError::Config(
                    "client_ca_file is required when mTLS is enabled".to_string(),
                ));
            }
            if tls.mtls != MtlsMode::Off && tls.client_crl_file.is_none() {
                return Err(CoreError::Config(
                    "client_crl_file is required when mTLS is enabled".to_string(),
                ));
            }
            if tls.mtls == MtlsMode::Off && tls.client_crl_file.is_some() {
                return Err(CoreError::Config(
                    "client_crl_file requires mTLS to be enabled".to_string(),
                ));
            }
            if !tls.validate_certificate && tls.crl_file.is_some() {
                return Err(CoreError::Config(
                    "tls.crl_file requires tls.validate_certificate=true".to_string(),
                ));
            }
            for sni in &tls.allowed_sni {
                validate_sni_pattern(sni)?;
            }
        }
        if self.quic.as_ref().is_some_and(|quic| quic.enabled) && self.tls.is_none() {
            return Err(CoreError::Config(
                "QUIC requires TLS configuration".to_string(),
            ));
        }
        if let Some(quic) = &self.quic {
            if !self.listen.allow_non_loopback && !quic.effective_host(&self.listen).is_loopback() {
                return Err(CoreError::Config(
                    "quic.host must be loopback unless listen.allow_non_loopback is true"
                        .to_string(),
                ));
            }
            for network in &quic.allowed_client_networks {
                validate_bounded_network(network, "quic.allowed_client_networks entry")?;
            }
            if quic.max_concurrent_bidi_streams == 0
                || quic.max_concurrent_uni_streams == 0
                || quic.max_idle_timeout_ms == 0
                || quic.max_inflight_handshakes == 0
                || quic.handshake_timeout_ms == 0
                || quic.stream_receive_window_bytes < 16_384
                || quic.connection_receive_window_bytes < quic.stream_receive_window_bytes
                || !(1200..=65527).contains(&quic.max_udp_payload_size)
            {
                return Err(CoreError::Config("invalid QUIC limits".to_string()));
            }
            if quic.enabled
                && self
                    .tls
                    .as_ref()
                    .is_some_and(|tls| tls.min_version != TlsMinVersion::Tls13)
            {
                return Err(CoreError::Config(
                    "QUIC requires tls.min_version=tls13".to_string(),
                ));
            }
        }
        for method in &self.policy.allowed_methods {
            validate_method(method)?;
            if matches!(method.as_str(), "CONNECT" | "TRACE") {
                return Err(CoreError::Config(
                    "CONNECT and TRACE are not allowed in the native request policy".to_string(),
                ));
            }
        }
        if !self
            .policy
            .allowed_methods
            .iter()
            .any(|value| value == "GET")
        {
            return Err(CoreError::Config(
                "policy.allowed_methods must include GET".to_string(),
            ));
        }
        if self.policy.max_path_bytes == 0 || self.policy.max_query_bytes == 0 {
            return Err(CoreError::Config(
                "path/query limits must be positive".to_string(),
            ));
        }
        if !self.policy.rate_limit.requests_per_second.is_finite()
            || self.policy.rate_limit.requests_per_second <= 0.0
            || !self.policy.rate_limit.burst.is_finite()
            || self.policy.rate_limit.burst < 1.0
            || self.policy.rate_limit.max_entries == 0
        {
            return Err(CoreError::Config(
                "invalid request rate-limit configuration".to_string(),
            ));
        }
        if self.agent.enabled
            && (self.agent.max_entries == 0
                || self.agent.window_seconds == 0
                || self.agent.max_requests_per_window == 0
                || self.agent.max_distinct_paths == 0
                || self.agent.max_distinct_methods == 0
                || self.agent.max_user_agent_changes == 0)
        {
            return Err(CoreError::Config(
                "invalid AI Agent detection limits".to_string(),
            ));
        }
        if self.bans.enabled
            && (self.bans.ttl_seconds == 0
                || self.bans.max_ttl_seconds == 0
                || self.bans.ttl_seconds > self.bans.max_ttl_seconds
                || self.bans.max_entries == 0
                || self.bans.violation_threshold == 0
                || self.bans.violation_window_seconds == 0
                || self.bans.response_violation_threshold == 0
                || self.bans.response_violation_window_seconds == 0)
        {
            return Err(CoreError::Config(
                "invalid automatic ban configuration".to_string(),
            ));
        }
        let mut route_names = std::collections::HashSet::new();
        for route in &self.routes {
            validate_route(route)?;
            if !route_names.insert(route.name.clone()) {
                return Err(CoreError::Config(format!(
                    "duplicate route name: {}",
                    route.name
                )));
            }
        }
        Ok(())
    }
}

fn resolve_existing(base: &Path, path: &Path, field: &str) -> Result<PathBuf> {
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    ensure_regular_file(&resolved, field)?;
    Ok(resolved)
}

fn resolve_for_output(base: &Path, path: &Path, field: &str) -> Result<PathBuf> {
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    if resolved.parent().is_some_and(|parent| !parent.exists()) {
        return Err(CoreError::Config(format!(
            "{field} parent directory does not exist"
        )));
    }
    Ok(resolved)
}

fn ensure_regular_file(path: &Path, field: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| CoreError::Config(format!("{field} is not readable: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(CoreError::Config(format!("{field} must not be a symlink")));
    }
    if !metadata.is_file() {
        return Err(CoreError::Config(format!("{field} must be a regular file")));
    }
    Ok(())
}

fn validate_proxy_protocol(config: &ProxyProtocolConfig) -> Result<()> {
    if !(100..=30_000).contains(&config.header_timeout_ms) {
        return Err(CoreError::Config(
            "proxy_protocol.header_timeout_ms must be between 100 and 30000".to_string(),
        ));
    }
    if config.mode == ProxyProtocolMode::Off {
        if !config.trusted_proxy_networks.is_empty() {
            return Err(CoreError::Config(
                "proxy_protocol.trusted_proxy_networks must be empty when mode is off".to_string(),
            ));
        }
        return Ok(());
    }
    if config.trusted_proxy_networks.is_empty() {
        return Err(CoreError::Config(
            "proxy_protocol.trusted_proxy_networks cannot be empty unless mode is off".to_string(),
        ));
    }

    let mut seen = std::collections::HashSet::new();
    for network in &config.trusted_proxy_networks {
        if !seen.insert(network.to_string()) {
            return Err(CoreError::Config(format!(
                "duplicate trusted proxy network: {network}"
            )));
        }
        validate_bounded_network(network, "trusted proxy network")?;
    }
    Ok(())
}

fn validate_bounded_network(network: &IpNet, field: &str) -> Result<()> {
    match network {
        IpNet::V4(network) => {
            let address = network.network();
            if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
                return Err(CoreError::Config(format!(
                    "{field} must be concrete unicast: {network}"
                )));
            }
            if network.prefix_len() == 32 {
                return Ok(());
            }
            let octets = address.octets();
            let minimum_prefix = if octets[0] == 10 {
                8
            } else if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                12
            } else if octets[0] == 192 && octets[1] == 168 {
                16
            } else if octets[0] == 127 {
                8
            } else if octets[0] == 169 && octets[1] == 254 {
                16
            } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                10
            } else {
                return Err(CoreError::Config(format!(
                    "{field} ranges must be private/loopback/link-local or an exact /32: {network}"
                )));
            };
            if network.prefix_len() < minimum_prefix {
                return Err(CoreError::Config(format!(
                    "{field} range is broader than its address family permits: {network}"
                )));
            }
        }
        IpNet::V6(network) => {
            let address = network.network();
            if address.is_unspecified() || address.is_multicast() {
                return Err(CoreError::Config(format!(
                    "{field} must be concrete unicast: {network}"
                )));
            }
            if network.prefix_len() == 128 {
                return Ok(());
            }
            let first_segment = address.segments()[0];
            let minimum_prefix = if first_segment & 0xfe00 == 0xfc00 {
                7
            } else if first_segment & 0xffc0 == 0xfe80 {
                10
            } else {
                return Err(CoreError::Config(format!(
                    "{field} ranges must be ULA/link-local or an exact /128: {network}"
                )));
            };
            if network.prefix_len() < minimum_prefix {
                return Err(CoreError::Config(format!(
                    "{field} range is broader than its address family permits: {network}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_method(value: &str) -> Result<()> {
    if value.is_empty()
        || !value.bytes().all(is_token_byte)
        || value.bytes().any(|byte| byte.is_ascii_lowercase())
    {
        return Err(CoreError::Config(format!(
            "invalid HTTP method in config: {value}"
        )));
    }
    Ok(())
}

fn validate_sni_pattern(value: &str) -> Result<()> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 || value.contains('/') || value.contains(':') {
        return Err(CoreError::Config(format!("invalid SNI pattern: {value}")));
    }
    let name = value.strip_prefix("*.").unwrap_or(&value);
    if name.is_empty() || name.split('.').any(|label| label.is_empty()) {
        return Err(CoreError::Config(format!("invalid SNI pattern: {value}")));
    }
    Ok(())
}

fn validate_route(route: &RouteConfig) -> Result<()> {
    if route.name.trim().is_empty() || route.name.len() > 128 {
        return Err(CoreError::Config(
            "route.name must be 1..=128 bytes".to_string(),
        ));
    }
    if !route.path_prefix.starts_with('/') || route.path_prefix.len() > 2048 {
        return Err(CoreError::Config(format!(
            "route {} has an invalid path_prefix",
            route.name
        )));
    }
    if route.path_prefix.contains(['\r', '\n', '\0', '?', '#']) {
        return Err(CoreError::Config(format!(
            "route {} has unsafe path_prefix characters",
            route.name
        )));
    }
    if let Some(host) = &route.host {
        if host.trim().is_empty()
            || host.len() > 253
            || host.contains(['/', '\\', ' ', '\r', '\n', '@'])
        {
            return Err(CoreError::Config(format!(
                "route {} has an invalid host",
                route.name
            )));
        }
    }
    for method in &route.methods {
        validate_method(method)?;
        if matches!(method.as_str(), "CONNECT" | "TRACE") {
            return Err(CoreError::Config(format!(
                "route {} cannot allow CONNECT/TRACE",
                route.name
            )));
        }
    }
    if route.websocket && route.grpc {
        return Err(CoreError::Config(format!(
            "route {} cannot be both websocket and grpc",
            route.name
        )));
    }
    if route.websocket {
        if route.ws_origins.is_empty() && !route.ws_allow_same_origin {
            return Err(CoreError::Config(format!(
                "route {} must configure ws_origins or ws_allow_same_origin",
                route.name
            )));
        }
        if route.ws_origins.len() > 64 {
            return Err(CoreError::Config(format!(
                "route {} has too many ws_origins",
                route.name
            )));
        }
        for origin in &route.ws_origins {
            validate_origin(origin)?;
        }
        if route
            .ws_origins
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != route.ws_origins.len()
        {
            return Err(CoreError::Config(format!(
                "route {} has duplicate ws_origins",
                route.name
            )));
        }
        if route
            .ws_subprotocols
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != route.ws_subprotocols.len()
        {
            return Err(CoreError::Config(format!(
                "route {} has duplicate ws_subprotocols",
                route.name
            )));
        }
        for protocol in &route.ws_subprotocols {
            if protocol.is_empty() || protocol.len() > 256 || !protocol.bytes().all(is_token_byte) {
                return Err(CoreError::Config(format!(
                    "route {} has an invalid ws_subprotocol",
                    route.name
                )));
            }
        }
        if route.ws_allow_extensions {
            return Err(CoreError::Config(format!(
                "route {} cannot enable ws_allow_extensions until compression inspection is enabled",
                route.name
            )));
        }
        if !route.methods.is_empty() && !route.methods.iter().any(|method| method == "GET") {
            return Err(CoreError::Config(format!(
                "route {} WebSocket policy must allow GET",
                route.name
            )));
        }
    }
    if route.grpc
        && !route.methods.is_empty()
        && !route.methods.iter().any(|method| method == "POST")
    {
        return Err(CoreError::Config(format!(
            "route {} gRPC policy must allow POST",
            route.name
        )));
    }
    if let Some(upstream) = &route.upstream {
        if upstream.host.trim().is_empty() || upstream.port == 0 {
            return Err(CoreError::Config(format!(
                "route {} has an invalid upstream",
                route.name
            )));
        }
    }
    Ok(())
}

fn validate_origin(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(CoreError::Config("invalid WebSocket origin".to_string()));
    }
    let Some((scheme, authority)) = value.split_once("://") else {
        return Err(CoreError::Config(
            "WebSocket origin must include a scheme".to_string(),
        ));
    };
    if !matches!(scheme, "http" | "https") {
        return Err(CoreError::Config(
            "WebSocket origin scheme must be http or https".to_string(),
        ));
    }
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@', '\\'])
        || authority.ends_with('.')
    {
        return Err(CoreError::Config(
            "invalid WebSocket origin authority".to_string(),
        ));
    }
    let host = if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(CoreError::Config(
                "invalid WebSocket origin IPv6".to_string(),
            ));
        };
        rest[..end]
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| CoreError::Config("invalid WebSocket origin IPv6".to_string()))?;
        let suffix = &rest[end + 1..];
        if !suffix.is_empty() && !suffix.strip_prefix(':').is_some_and(valid_port) {
            return Err(CoreError::Config(
                "invalid WebSocket origin port".to_string(),
            ));
        }
        &rest[..end]
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if port.is_some_and(|port| !valid_port(port)) {
            return Err(CoreError::Config(
                "invalid WebSocket origin port".to_string(),
            ));
        }
        host
    };
    if host.is_empty()
        || (host.parse::<std::net::Ipv4Addr>().is_err()
            && !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }))
    {
        return Err(CoreError::Config(
            "invalid WebSocket origin host".to_string(),
        ));
    }
    Ok(())
}

fn valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

pub fn is_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    ) || byte.is_ascii_alphanumeric()
}

pub fn sni_matches(pattern: &str, server_name: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let server_name = server_name
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if server_name.is_empty() || server_name.len() > 253 {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return server_name.len() > suffix.len() + 1
            && server_name.ends_with(suffix)
            && server_name.as_bytes()[server_name.len() - suffix.len() - 1] == b'.';
    }
    pattern == server_name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_strict_and_loopback_only() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.listen.host.is_loopback());
        assert!(!config
            .policy
            .allowed_methods
            .iter()
            .any(|value| value == "CONNECT"));
        assert_eq!(config.bans.violation_threshold, 500);
        assert_eq!(config.bans.response_violation_threshold, 500);
        let mut unsafe_config = config;
        unsafe_config.listen.host = "0.0.0.0".parse().unwrap();
        assert!(unsafe_config.validate().is_err());
    }

    #[test]
    fn duplicate_and_unknown_fields_are_rejected() {
        let unknown =
            serde_json::json!({"listen": {"host": "127.0.0.1", "port": 1, "surprise": true}});
        assert!(serde_json::from_value::<AppConfig>(unknown).is_err());
        let duplicate = r#"{"listen":{"host":"127.0.0.1","host":"127.0.0.1"}}"#;
        assert!(serde_json::from_str::<AppConfig>(duplicate).is_err());
    }

    #[test]
    fn sni_wildcards_are_single_suffix_matches() {
        assert!(sni_matches("*.example.test", "a.example.test"));
        assert!(sni_matches("*.example.test", "a.b.example.test"));
        assert!(!sni_matches("*.example.test", "badexample.test"));
        assert!(sni_matches("example.test", "example.test"));
    }

    #[test]
    fn proxy_protocol_requires_explicit_trusted_proxies() {
        let mut config = AppConfig::default();
        config.listen.proxy_protocol.mode = ProxyProtocolMode::Required;
        assert!(config.validate().is_err());

        config.listen.proxy_protocol.trusted_proxy_networks = vec!["127.0.0.1/32".parse().unwrap()];
        assert!(config.validate().is_ok());
        assert!(config
            .listen
            .proxy_protocol
            .trusts("127.0.0.1".parse().unwrap()));
        assert!(!config
            .listen
            .proxy_protocol
            .trusts("127.0.0.2".parse().unwrap()));
    }

    #[test]
    fn trusted_proxy_ranges_cannot_cover_public_internet() {
        let mut config = AppConfig::default();
        config.listen.proxy_protocol.mode = ProxyProtocolMode::Optional;

        config.listen.proxy_protocol.trusted_proxy_networks = vec!["0.0.0.0/0".parse().unwrap()];
        assert!(config.validate().is_err());

        config.listen.proxy_protocol.trusted_proxy_networks =
            vec!["203.0.113.0/24".parse().unwrap()];
        assert!(config.validate().is_err());

        config.listen.proxy_protocol.trusted_proxy_networks =
            vec!["203.0.113.9/32".parse().unwrap()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn disabling_proxy_protocol_requires_removing_trusted_ranges() {
        let mut config = AppConfig::default();
        config.listen.proxy_protocol.trusted_proxy_networks = vec!["127.0.0.1/32".parse().unwrap()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn quic_host_can_differ_and_requires_non_loopback_opt_in() {
        let mut config = AppConfig {
            quic: Some(QuicConfig {
                host: Some("127.0.0.2".parse().unwrap()),
                ..QuicConfig::default()
            }),
            ..AppConfig::default()
        };
        assert!(config.validate().is_ok());
        assert_eq!(
            config.quic.as_ref().unwrap().effective_host(&config.listen),
            "127.0.0.2".parse::<IpAddr>().unwrap()
        );

        config.quic.as_mut().unwrap().host = Some("203.0.113.10".parse().unwrap());
        assert!(config.validate().is_err());
        config.listen.allow_non_loopback = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn quic_client_allowlist_is_bounded_and_explicit() {
        let mut config = AppConfig {
            quic: Some(QuicConfig {
                allowed_client_networks: vec!["0.0.0.0/0".parse().unwrap()],
                ..QuicConfig::default()
            }),
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());

        config.quic.as_mut().unwrap().allowed_client_networks =
            vec!["198.51.100.132/32".parse().unwrap()];
        assert!(config.validate().is_ok());
        let quic = config.quic.as_ref().unwrap();
        assert!(quic.allows("198.51.100.132".parse().unwrap()));
        assert!(!quic.allows("198.51.100.133".parse().unwrap()));
    }
}
