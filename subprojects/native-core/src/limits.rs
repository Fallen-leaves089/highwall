use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{AgentMode, BanConfig};

#[derive(Clone)]
pub struct ConnectionBudget {
    global: Arc<Semaphore>,
    per_ip_limit: usize,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

pub struct ConnectionGuard {
    _global: OwnedSemaphorePermit,
    ip: IpAddr,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

pub struct PendingConnectionGuard {
    global: Option<OwnedSemaphorePermit>,
    per_ip_limit: usize,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl ConnectionBudget {
    pub fn new(max_connections: usize, per_ip_limit: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_connections)),
            per_ip_limit,
            per_ip: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnectionGuard> {
        self.try_acquire_pending()?.try_classify(ip)
    }

    pub fn try_acquire_pending(&self) -> Option<PendingConnectionGuard> {
        let global = self.global.clone().try_acquire_owned().ok()?;
        Some(PendingConnectionGuard {
            global: Some(global),
            per_ip_limit: self.per_ip_limit,
            per_ip: self.per_ip.clone(),
        })
    }

    pub fn current_for(&self, ip: IpAddr) -> usize {
        lock(&self.per_ip).get(&ip).copied().unwrap_or(0)
    }
}

impl PendingConnectionGuard {
    pub fn try_classify(mut self, ip: IpAddr) -> Option<ConnectionGuard> {
        let global = self.global.take()?;
        let mut per_ip = lock(&self.per_ip);
        let count = per_ip.entry(ip).or_insert(0);
        if *count >= self.per_ip_limit {
            return None;
        }
        *count += 1;
        Some(ConnectionGuard {
            _global: global,
            ip,
            per_ip: self.per_ip.clone(),
        })
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut per_ip = lock(&self.per_ip);
        if let Some(count) = per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                per_ip.remove(&self.ip);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    pub permit: bool,
    pub remaining: usize,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

#[derive(Clone)]
pub struct RequestRateLimiter {
    rate_per_second: f64,
    burst: f64,
    buckets: Arc<Mutex<HashMap<IpAddr, Bucket>>>,
    max_entries: usize,
}

impl RequestRateLimiter {
    pub fn new(rate_per_second: f64, burst: f64, max_entries: usize) -> Self {
        Self {
            rate_per_second: rate_per_second.max(0.1),
            burst: burst.max(1.0),
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_entries: max_entries.max(1),
        }
    }

    pub fn check(&self, ip: IpAddr) -> RateLimit {
        let now = Instant::now();
        let mut buckets = lock(&self.buckets);
        if buckets.len() >= self.max_entries && !buckets.contains_key(&ip) {
            buckets.retain(|_, bucket| now.duration_since(bucket.last) < Duration::from_secs(600));
            if buckets.len() >= self.max_entries {
                return RateLimit {
                    permit: false,
                    remaining: 0,
                };
            }
        }
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate_per_second).min(self.burst);
        bucket.last = now;
        if bucket.tokens < 1.0 {
            RateLimit {
                permit: false,
                remaining: 0,
            }
        } else {
            bucket.tokens -= 1.0;
            RateLimit {
                permit: true,
                remaining: bucket.tokens.floor() as usize,
            }
        }
    }
}

#[derive(Debug, Clone)]
struct BanEntry {
    expires_at: Instant,
    rule_id: String,
}

#[derive(Debug)]
struct ViolationWindow {
    events: VecDeque<(Instant, String)>,
}

#[derive(Clone)]
pub struct BanTable {
    config: BanConfig,
    entries: Arc<Mutex<HashMap<IpAddr, BanEntry>>>,
    violations: Arc<Mutex<HashMap<IpAddr, ViolationWindow>>>,
    response_violations: Arc<Mutex<HashMap<IpAddr, ViolationWindow>>>,
}

impl BanTable {
    pub fn new(config: BanConfig) -> Self {
        Self {
            config,
            entries: Arc::new(Mutex::new(HashMap::new())),
            violations: Arc::new(Mutex::new(HashMap::new())),
            response_violations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_banned(&self, ip: IpAddr) -> Option<String> {
        if !self.config.enabled {
            return None;
        }
        let now = Instant::now();
        let mut entries = lock(&self.entries);
        entries.retain(|_, entry| entry.expires_at > now);
        entries.get(&ip).map(|entry| entry.rule_id.clone())
    }

    pub fn remaining(&self, ip: IpAddr) -> Option<Duration> {
        if !self.config.enabled {
            return None;
        }
        let now = Instant::now();
        let mut entries = lock(&self.entries);
        entries.retain(|_, entry| entry.expires_at > now);
        entries
            .get(&ip)
            .and_then(|entry| entry.expires_at.checked_duration_since(now))
    }

    pub fn ban(&self, ip: IpAddr, ttl: Duration, rule_id: impl Into<String>) -> bool {
        if !self.config.enabled {
            return false;
        }
        let ttl = ttl.min(Duration::from_secs(self.config.max_ttl_seconds));
        let mut entries = lock(&self.entries);
        if entries.len() >= self.config.max_entries && !entries.contains_key(&ip) {
            return false;
        }
        entries.insert(
            ip,
            BanEntry {
                expires_at: Instant::now() + ttl,
                rule_id: rule_id.into(),
            },
        );
        true
    }

    pub fn unban(&self, ip: IpAddr) -> bool {
        lock(&self.entries).remove(&ip).is_some()
    }

    pub fn note_violation(&self, ip: IpAddr, rule_id: impl Into<String>) -> bool {
        self.note_violation_in(
            self.violations.as_ref(),
            ip,
            rule_id.into(),
            self.config.violation_threshold,
            self.config.violation_window_seconds,
        )
    }

    pub fn note_response_violation(&self, ip: IpAddr, rule_id: impl Into<String>) -> bool {
        self.note_violation_in(
            self.response_violations.as_ref(),
            ip,
            rule_id.into(),
            self.config.response_violation_threshold,
            self.config.response_violation_window_seconds,
        )
    }

    fn note_violation_in(
        &self,
        violations: &Mutex<HashMap<IpAddr, ViolationWindow>>,
        ip: IpAddr,
        rule_id: String,
        threshold: usize,
        window_seconds: u64,
    ) -> bool {
        if !self.config.enabled {
            return false;
        }
        if lock(&self.entries)
            .get(&ip)
            .is_some_and(|entry| entry.expires_at > Instant::now())
        {
            return false;
        }
        let now = Instant::now();
        let window = Duration::from_secs(window_seconds.max(1));
        let mut violations = lock(violations);
        if violations.len() > self.config.max_entries.saturating_mul(4) {
            violations.retain(|_, entry| {
                entry
                    .events
                    .back()
                    .is_some_and(|(at, _)| now.duration_since(*at) < window)
            });
        }
        let entry = violations.entry(ip).or_insert_with(|| ViolationWindow {
            events: VecDeque::new(),
        });
        while entry
            .events
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) > window)
        {
            entry.events.pop_front();
        }
        entry.events.push_back((now, rule_id.clone()));
        if entry.events.len() < threshold {
            return false;
        }
        let last_rule = entry
            .events
            .back()
            .map(|(_, rule)| rule.clone())
            .unwrap_or(rule_id);
        violations.remove(&ip);
        drop(violations);
        self.ban(ip, Duration::from_secs(self.config.ttl_seconds), last_rule)
    }

    pub fn len(&self) -> usize {
        lock(&self.entries).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Default)]
pub struct AgentSignal {
    pub requests: usize,
    pub distinct_paths: usize,
    pub distinct_methods: usize,
    pub user_agent_changes: usize,
    pub score: usize,
    pub confirmed: bool,
    pub anomalous: bool,
    pub reasons: Vec<&'static str>,
}

struct AgentWindow {
    started: Instant,
    requests: usize,
    paths: HashSet<u64>,
    methods: HashSet<u64>,
    user_agents: HashSet<u64>,
}

#[derive(Clone)]
pub struct AgentTracker {
    enabled: bool,
    mode: AgentMode,
    max_entries: usize,
    window: Duration,
    max_requests: usize,
    max_distinct_paths: usize,
    max_distinct_methods: usize,
    max_user_agent_changes: usize,
    windows: Arc<Mutex<HashMap<IpAddr, AgentWindow>>>,
}

impl AgentTracker {
    pub fn new(config: &crate::config::AgentConfig) -> Self {
        Self {
            enabled: config.enabled,
            mode: config.mode,
            max_entries: config.max_entries.max(1),
            window: Duration::from_secs(config.window_seconds.max(1)),
            max_requests: config.max_requests_per_window.max(1),
            max_distinct_paths: config.max_distinct_paths.max(1),
            max_distinct_methods: config.max_distinct_methods.max(1),
            max_user_agent_changes: config.max_user_agent_changes.max(1),
            windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn observe(
        &self,
        ip: IpAddr,
        path_hash: u64,
        method_hash: u64,
        user_agent_hash: Option<u64>,
    ) -> AgentSignal {
        if !self.enabled {
            return AgentSignal::default();
        }
        let now = Instant::now();
        let mut windows = lock(&self.windows);
        if windows.len() >= self.max_entries && !windows.contains_key(&ip) {
            windows.retain(|_, window| now.duration_since(window.started) < self.window);
            if windows.len() >= self.max_entries {
                if let Some(victim) = windows.keys().next().copied() {
                    windows.remove(&victim);
                }
            }
        }
        let window = windows.entry(ip).or_insert_with(|| AgentWindow {
            started: now,
            requests: 0,
            paths: HashSet::new(),
            methods: HashSet::new(),
            user_agents: HashSet::new(),
        });
        if now.duration_since(window.started) >= self.window {
            *window = AgentWindow {
                started: now,
                requests: 0,
                paths: HashSet::new(),
                methods: HashSet::new(),
                user_agents: HashSet::new(),
            };
        }
        window.requests = window.requests.saturating_add(1);
        insert_capped(&mut window.paths, path_hash, self.max_distinct_paths);
        insert_capped(&mut window.methods, method_hash, self.max_distinct_methods);
        if let Some(hash) = user_agent_hash {
            insert_capped(&mut window.user_agents, hash, self.max_user_agent_changes);
        }
        let requests = window.requests;
        let distinct_paths = window.paths.len();
        let distinct_methods = window.methods.len();
        let user_agent_changes = window.user_agents.len();
        let mut reasons = Vec::new();
        if requests > self.max_requests {
            reasons.push("request-rate");
        }
        if distinct_paths > self.max_distinct_paths {
            reasons.push("path-diversity");
        }
        if distinct_methods > self.max_distinct_methods {
            reasons.push("method-diversity");
        }
        if user_agent_changes > self.max_user_agent_changes {
            reasons.push("user-agent-churn");
        }
        let score = reasons.len();
        let anomalous = !reasons.is_empty() && !matches!(self.mode, AgentMode::Observe);
        let confirmed = self.mode == AgentMode::Confirmed && score >= 2;
        AgentSignal {
            requests,
            distinct_paths,
            distinct_methods,
            user_agent_changes,
            score,
            confirmed,
            anomalous,
            reasons,
        }
    }
}

fn insert_capped(values: &mut HashSet<u64>, value: u64, threshold: usize) {
    if values.contains(&value) || values.len() <= threshold {
        values.insert(value);
    }
}

pub struct H2ConnectionBudget {
    requests: usize,
    max_requests: usize,
    reset_errors: usize,
    max_reset_errors: usize,
}

impl H2ConnectionBudget {
    pub fn new(max_requests: usize, max_reset_errors: usize) -> Self {
        Self {
            requests: 0,
            max_requests,
            reset_errors: 0,
            max_reset_errors,
        }
    }

    pub fn accept_request(&mut self) -> bool {
        self.requests += 1;
        self.requests <= self.max_requests
    }

    pub fn reset_error(&mut self) -> bool {
        self.reset_errors += 1;
        self.reset_errors > self.max_reset_errors
    }

    pub fn requests(&self) -> usize {
        self.requests
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_ip_and_global_limits_are_enforced() {
        let budget = ConnectionBudget::new(2, 1);
        let first = budget.try_acquire("192.0.2.1".parse().unwrap()).unwrap();
        assert!(budget.try_acquire("192.0.2.1".parse().unwrap()).is_none());
        let second = budget.try_acquire("192.0.2.2".parse().unwrap()).unwrap();
        assert!(budget.try_acquire("192.0.2.3".parse().unwrap()).is_none());
        drop(first);
        assert!(budget.try_acquire("192.0.2.3".parse().unwrap()).is_some());
        drop(second);
    }

    #[test]
    fn pending_connections_classify_against_the_forwarded_source() {
        let budget = ConnectionBudget::new(3, 1);
        let pending_a = budget.try_acquire_pending().unwrap();
        let pending_b = budget.try_acquire_pending().unwrap();
        let first = pending_a
            .try_classify("203.0.113.10".parse().unwrap())
            .unwrap();
        let second = pending_b
            .try_classify("203.0.113.11".parse().unwrap())
            .unwrap();

        let pending_duplicate = budget.try_acquire_pending().unwrap();
        assert!(pending_duplicate
            .try_classify("203.0.113.10".parse().unwrap())
            .is_none());
        assert_eq!(budget.current_for("203.0.113.10".parse().unwrap()), 1);
        assert_eq!(budget.current_for("203.0.113.11".parse().unwrap()), 1);
        drop(first);
        drop(second);
    }

    #[test]
    fn ban_is_exact_ip_and_expires() {
        let table = BanTable::new(BanConfig {
            enabled: true,
            ttl_seconds: 1,
            max_ttl_seconds: 1,
            max_entries: 2,
            violation_threshold: 2,
            violation_window_seconds: 60,
            response_violation_threshold: 3,
            response_violation_window_seconds: 60,
        });
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert!(table.ban(ip, Duration::from_secs(1), "test"));
        assert_eq!(table.is_banned(ip).as_deref(), Some("test"));
        assert!(table.remaining(ip).is_some_and(
            |remaining| remaining > Duration::ZERO && remaining <= Duration::from_secs(1)
        ));
        assert!(table.is_banned("192.0.2.11".parse().unwrap()).is_none());
    }

    #[test]
    fn response_violations_use_an_independent_threshold() {
        let table = BanTable::new(BanConfig {
            enabled: true,
            ttl_seconds: 1,
            max_ttl_seconds: 1,
            max_entries: 2,
            violation_threshold: 1,
            violation_window_seconds: 60,
            response_violation_threshold: 3,
            response_violation_window_seconds: 60,
        });
        let ip: IpAddr = "192.0.2.12".parse().unwrap();
        assert!(!table.note_response_violation(ip, "HW-NATIVE-DLP-002"));
        assert!(!table.note_response_violation(ip, "HW-NATIVE-DLP-002"));
        assert!(table.is_banned(ip).is_none());
        assert!(table.note_response_violation(ip, "HW-NATIVE-DLP-002"));
        assert_eq!(table.is_banned(ip).as_deref(), Some("HW-NATIVE-DLP-002"));
    }

    #[test]
    fn agent_confirmation_requires_two_independent_signals() {
        let tracker = AgentTracker::new(&crate::config::AgentConfig {
            enabled: true,
            mode: crate::config::AgentMode::Confirmed,
            max_entries: 16_384,
            window_seconds: 60,
            max_requests_per_window: 2,
            max_distinct_paths: 100,
            max_distinct_methods: 1,
            max_user_agent_changes: 10,
        });
        let ip: IpAddr = "192.0.2.20".parse().unwrap();
        assert!(!tracker.observe(ip, 1, 1, Some(1)).anomalous);
        assert!(!tracker.observe(ip, 1, 1, Some(1)).anomalous);
        let single = tracker.observe(ip, 1, 1, Some(1));
        assert_eq!(single.score, 1);
        assert!(single.anomalous);
        assert!(!single.confirmed);
        let confirmed = tracker.observe(ip, 1, 2, Some(1));
        assert_eq!(confirmed.score, 2);
        assert!(confirmed.confirmed);
    }

    #[test]
    fn agent_observe_mode_never_enforces() {
        let tracker = AgentTracker::new(&crate::config::AgentConfig {
            enabled: true,
            mode: crate::config::AgentMode::Observe,
            max_entries: 16_384,
            window_seconds: 60,
            max_requests_per_window: 1,
            max_distinct_paths: 100,
            max_distinct_methods: 100,
            max_user_agent_changes: 100,
        });
        let ip: IpAddr = "192.0.2.21".parse().unwrap();
        tracker.observe(ip, 1, 1, Some(1));
        let signal = tracker.observe(ip, 1, 1, Some(1));
        assert!(signal.score >= 1);
        assert!(!signal.anomalous);
        assert!(!signal.confirmed);
    }

    #[test]
    fn default_agent_profile_avoids_low_ua_churn_false_positives() {
        let tracker = AgentTracker::new(&crate::config::AgentConfig::default());
        let ip: IpAddr = "192.0.2.22".parse().unwrap();
        for value in 0..12_u64 {
            let signal = tracker.observe(ip, 1, 1, Some(value));
            assert!(
                !signal.anomalous,
                "the default profile must allow 12 distinct UAs: {signal:?}"
            );
        }
        let signal = tracker.observe(ip, 1, 1, Some(13));
        assert!(signal.anomalous);
        assert!(!signal.confirmed);
        assert_eq!(signal.reasons, vec!["user-agent-churn"]);
    }

    #[test]
    fn agent_tracking_memory_is_bounded_per_source_and_globally() {
        let tracker = AgentTracker::new(&crate::config::AgentConfig {
            enabled: true,
            mode: crate::config::AgentMode::Observe,
            max_entries: 2,
            window_seconds: 60,
            max_requests_per_window: 10_000,
            max_distinct_paths: 4,
            max_distinct_methods: 2,
            max_user_agent_changes: 2,
        });
        let first: IpAddr = "192.0.2.30".parse().unwrap();
        for value in 0..1_000_u64 {
            tracker.observe(first, value, value, Some(value));
        }
        {
            let windows = lock(&tracker.windows);
            let window = windows.get(&first).unwrap();
            assert_eq!(window.requests, 1_000);
            assert_eq!(window.paths.len(), 5);
            assert_eq!(window.methods.len(), 3);
            assert_eq!(window.user_agents.len(), 3);
        }
        for octet in 31..35 {
            let ip: IpAddr = format!("192.0.2.{octet}").parse().unwrap();
            tracker.observe(ip, 1, 1, Some(1));
        }
        assert_eq!(lock(&tracker.windows).len(), 2);
    }
}
