use std::{sync::Arc, time::Instant};

use crate::{
    audit::AuditHandle,
    config::AppConfig,
    error::Result,
    limits::{AgentTracker, BanTable, ConnectionBudget, RequestRateLimiter},
    tls::{build_tls_bundle, install_provider, TlsBundle},
};

pub struct AppState {
    pub config: Arc<AppConfig>,
    pub audit: AuditHandle,
    pub connections: ConnectionBudget,
    pub bans: BanTable,
    pub agent: AgentTracker,
    pub rate: RequestRateLimiter,
    pub handshake_rate: RequestRateLimiter,
    pub tls: Option<TlsBundle>,
    pub started_at: Instant,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Arc<Self>> {
        let tls = if let Some(tls_config) = &config.tls {
            install_provider()?;
            Some(build_tls_bundle(
                tls_config,
                config.quic.as_ref().is_some_and(|quic| quic.enabled),
            )?)
        } else {
            None
        };
        let audit = AuditHandle::start(&config.audit).await?;
        let config = Arc::new(config);
        Ok(Arc::new(Self {
            connections: ConnectionBudget::new(
                config.limits.max_connections,
                config.limits.max_connections_per_ip,
            ),
            bans: BanTable::new(config.bans.clone()),
            agent: AgentTracker::new(&config.agent),
            rate: RequestRateLimiter::new(
                config.policy.rate_limit.requests_per_second,
                config.policy.rate_limit.burst,
                config.policy.rate_limit.max_entries,
            ),
            handshake_rate: RequestRateLimiter::new(
                config.limits.max_tls_handshakes_per_second_per_ip,
                config.limits.max_tls_handshake_burst_per_ip,
                config.limits.max_tls_handshake_entries,
            ),
            audit,
            tls,
            started_at: Instant::now(),
            config,
        }))
    }
}
