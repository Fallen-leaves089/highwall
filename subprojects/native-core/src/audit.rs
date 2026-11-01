use std::{
    fs::OpenOptions,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tokio::{io::AsyncWriteExt, sync::mpsc};

use crate::{
    config::AuditConfig,
    error::{CoreError, Result},
};

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub schema: &'static str,
    pub timestamp_unix_ms: u128,
    pub request_id: u64,
    pub peer: String,
    pub protocol: String,
    pub method: String,
    pub path: String,
    pub route: String,
    pub decision: String,
    pub status: u16,
    pub rule_ids: Vec<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: u64,
        peer: impl Into<String>,
        protocol: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        route: impl Into<String>,
        decision: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            schema: "highwall.native.audit.v1",
            timestamp_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            request_id,
            peer: peer.into(),
            protocol: protocol.into(),
            method: method.into(),
            path: path.into(),
            route: route.into(),
            decision: decision.into(),
            status,
            rule_ids: Vec::new(),
            bytes_in: 0,
            bytes_out: 0,
            duration_ms: 0,
            tls_server_name: None,
            tls_version: None,
            alpn: None,
            detail: None,
        }
    }
}

#[derive(Clone)]
pub struct AuditHandle {
    tx: Option<mpsc::Sender<AuditEvent>>,
    healthy: Arc<AtomicBool>,
    fail_closed: bool,
    enabled: bool,
}

impl AuditHandle {
    pub async fn start(config: &AuditConfig) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                tx: None,
                healthy: Arc::new(AtomicBool::new(true)),
                fail_closed: config.fail_closed,
                enabled: false,
            });
        }
        let path = config.path.clone();
        let file = open_audit_file(&path)?;
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(config.queue_capacity);
        let healthy = Arc::new(AtomicBool::new(true));
        let writer_healthy = healthy.clone();
        tokio::spawn(async move {
            let mut file = file;
            while let Some(event) = rx.recv().await {
                let mut line = match serde_json::to_vec(&event) {
                    Ok(line) => line,
                    Err(_) => {
                        writer_healthy.store(false, Ordering::Release);
                        break;
                    }
                };
                line.push(b'\n');
                if file.write_all(&line).await.is_err() || file.flush().await.is_err() {
                    writer_healthy.store(false, Ordering::Release);
                    break;
                }
            }
            writer_healthy.store(false, Ordering::Release);
        });
        Ok(Self {
            tx: Some(tx),
            healthy,
            fail_closed: config.fail_closed,
            enabled: true,
        })
    }

    pub fn is_healthy(&self) -> bool {
        !self.enabled || !self.fail_closed || self.healthy.load(Ordering::Acquire)
    }

    pub fn record(&self, event: AuditEvent) -> bool {
        let Some(tx) = &self.tx else {
            return true;
        };
        if !self.is_healthy() {
            return false;
        }
        match tx.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                if self.fail_closed {
                    self.healthy.store(false, Ordering::Release);
                    false
                } else {
                    true
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.healthy.store(false, Ordering::Release);
                !self.fail_closed
            }
        }
    }

    pub fn require_available(&self) -> Result<()> {
        if self.is_healthy() {
            Ok(())
        } else {
            Err(CoreError::AuditUnavailable)
        }
    }
}

fn open_audit_file(path: &PathBuf) -> Result<tokio::fs::File> {
    let std_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| {
            CoreError::Config(format!(
                "cannot open audit path {}: {error}",
                path.display()
            ))
        })?;
    Ok(tokio::fs::File::from_std(std_file))
}

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub fn next_request_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn normalized_path(target: &str) -> String {
    let path = target.split('?').next().unwrap_or("/");
    let mut output = String::with_capacity(path.len().min(512));
    for character in path.chars().take(512) {
        if character.is_control() {
            output.push('?');
        } else {
            output.push(character);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_control_characters_are_not_written_to_path() {
        assert_eq!(normalized_path("/safe?token=secret"), "/safe");
        assert_eq!(normalized_path("/safe\x00path"), "/safe?path");
    }

    #[tokio::test]
    async fn audit_event_reaches_file() {
        let path = std::env::temp_dir().join(format!(
            "highwall-native-audit-{}-{}.jsonl",
            std::process::id(),
            next_request_id()
        ));
        let config = AuditConfig {
            enabled: true,
            path: path.clone(),
            queue_capacity: 8,
            fail_closed: true,
        };
        let audit = AuditHandle::start(&config).await.unwrap();
        assert!(audit.record(AuditEvent::new(
            1,
            "127.0.0.1:1",
            "h1",
            "GET",
            "/",
            "default",
            "allow",
            200
        )));
        for _ in 0..50 {
            if path.metadata().is_ok_and(|metadata| metadata.len() > 0) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"request_id\":1"));
        assert!(!content.contains("secret"));
        let _ = std::fs::remove_file(path);
    }
}
