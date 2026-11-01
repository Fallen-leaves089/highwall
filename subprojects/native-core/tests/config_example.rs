use std::path::Path;

use highwall_native_core::config::AppConfig;

#[test]
fn example_config_is_valid_and_documents_bounded_defaults() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.json");
    let config = AppConfig::load(path).expect("config.example.json must remain loadable");
    assert_eq!(config.limits.h2_idle_timeout_ms, 60_000);
    assert_eq!(config.agent.max_entries, 16_384);
    assert!(config.tls.is_none());
    assert!(config.quic.is_none());
}
