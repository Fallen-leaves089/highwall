use std::collections::BTreeSet;

use base64::Engine;

use crate::{
    config::{AppConfig, RouteConfig, WafConfig},
    http::{header_tokens, HeaderField, RequestHead},
    inspect::InspectedBody,
};

pub const RULE_ROUTE: &str = "HW-NATIVE-ROUTE-001";
pub const RULE_METHOD: &str = "HW-NATIVE-METHOD-001";
pub const RULE_TARGET: &str = "HW-NATIVE-TARGET-001";
pub const RULE_PATH_LIMIT: &str = "HW-NATIVE-PATH-001";
pub const RULE_TRAVERSAL: &str = "HW-NATIVE-WAF-001";
pub const RULE_SQLI: &str = "HW-NATIVE-WAF-002";
pub const RULE_XSS: &str = "HW-NATIVE-WAF-003";
pub const RULE_COMMAND: &str = "HW-NATIVE-WAF-004";
pub const RULE_LOG4J: &str = "HW-NATIVE-WAF-005";
pub const RULE_SCANNER: &str = "HW-NATIVE-WAF-006";
pub const RULE_WAF_AMBIGUOUS_ENCODING: &str = "HW-NATIVE-WAF-007";
pub const RULE_DLP_AWS: &str = "HW-NATIVE-DLP-001";
pub const RULE_DLP_PRIVATE_KEY: &str = "HW-NATIVE-DLP-002";
pub const RULE_DLP_TOKEN: &str = "HW-NATIVE-DLP-003";
pub const RULE_DLP_HIGH_ENTROPY: &str = "HW-NATIVE-DLP-004";
pub const RULE_DLP_AMBIGUOUS_ENCODING: &str = "HW-NATIVE-DLP-005";
pub const RULE_AGENT: &str = "HW-NATIVE-AGENT-001";
pub const RULE_BAN: &str = "HW-NATIVE-BAN-001";
pub const RULE_UPGRADE: &str = "HW-NATIVE-UPGRADE-001";
pub const RULE_GRPC: &str = "HW-NATIVE-GRPC-001";

const DLP_MAX_DECODE_DEPTH: usize = 3;
const DLP_MAX_DECODE_CANDIDATES: usize = 512;
const DLP_MAX_DECODE_INPUT_BYTES: usize = 4 * 1024 * 1024;
const DLP_MIN_BASE64_INPUT_BYTES: usize = 24;
const DLP_MIN_DECODED_BYTES: usize = 8;
const WAF_MAX_DECODE_DEPTH: usize = 3;
const WAF_MAX_BASE64_CANDIDATES: usize = 64;
const WAF_MAX_BASE64_INPUT_BYTES: usize = 16 * 1024;
const WAF_MAX_DECODED_BYTES: usize = 1024 * 1024;
const WAF_SCAN_WINDOW_BYTES: usize = 64 * 1024;
const WAF_SCAN_OVERLAP_BYTES: usize = 1024;
const DLP_PRIVATE_KEY_MARKERS: &[&str] = &[
    "BEGINPRIVATEKEY",
    "BEGINRSAPRIVATEKEY",
    "BEGINOPENSSHPRIVATEKEY",
    "BEGINECPRIVATEKEY",
    "BEGINDSAPRIVATEKEY",
    "BEGINENCRYPTEDPRIVATEKEY",
    "BEGINPGPPRIVATEKEYBLOCK",
    "BEGINSSH2ENCRYPTEDPRIVATEKEY",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny,
    RateLimit,
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub status: u16,
    pub rule_ids: Vec<String>,
    pub reason: String,
    pub route: Option<RouteConfig>,
}

impl PolicyDecision {
    fn allow(route: RouteConfig) -> Self {
        Self {
            action: PolicyAction::Allow,
            status: 200,
            rule_ids: Vec::new(),
            reason: "allowed".to_string(),
            route: Some(route),
        }
    }

    fn deny(status: u16, rule_id: &str, reason: impl Into<String>) -> Self {
        Self {
            action: PolicyAction::Deny,
            status,
            rule_ids: vec![rule_id.to_string()],
            reason: reason.into(),
            route: None,
        }
    }

    fn rate_limit(rule_id: &str, reason: impl Into<String>) -> Self {
        Self {
            action: PolicyAction::RateLimit,
            status: 429,
            rule_ids: vec![rule_id.to_string()],
            reason: reason.into(),
            route: None,
        }
    }
}

pub struct RequestContext<'a> {
    pub head: &'a RequestHead,
    pub body: &'a [u8],
    pub inspected_body: Option<&'a InspectedBody>,
    pub trailers: &'a [HeaderField],
    pub banned_rule: Option<String>,
    pub agent_anomalous: bool,
    pub agent_confirmed: bool,
}

pub fn evaluate_request(config: &AppConfig, context: &RequestContext<'_>) -> PolicyDecision {
    if let Some(rule) = &context.banned_rule {
        return PolicyDecision::deny(403, RULE_BAN, format!("source is banned by {rule}"));
    }
    let head = context.head;
    if config.policy.require_host && head.host.is_empty() {
        return PolicyDecision::deny(400, RULE_TARGET, "Host header is required");
    }
    if head.path.len() > config.policy.max_path_bytes
        || head
            .query
            .as_ref()
            .is_some_and(|query| query.len() > config.policy.max_query_bytes)
    {
        return PolicyDecision::deny(414, RULE_PATH_LIMIT, "request target is too large");
    }
    if !config
        .policy
        .allowed_methods
        .iter()
        .any(|method| method == &head.method)
    {
        return PolicyDecision::deny(405, RULE_METHOD, "request method is not allowed");
    }
    let Some(route) = select_route(config, head) else {
        return PolicyDecision::deny(403, RULE_ROUTE, "no explicit route allows this request");
    };
    if context.agent_confirmed {
        return PolicyDecision::deny(403, RULE_AGENT, "multiple automation signals confirmed");
    }
    if context.agent_anomalous {
        return PolicyDecision::rate_limit(
            RULE_AGENT,
            "automation-like request shape exceeded budget",
        );
    }
    if head.upgrade.is_some() && !route.websocket {
        return PolicyDecision::deny(
            403,
            RULE_UPGRADE,
            "this route does not allow WebSocket upgrades",
        );
    }
    if head.is_grpc() && !route.grpc {
        return PolicyDecision::deny(415, RULE_GRPC, "this route does not allow gRPC");
    }
    if route.grpc && !head.is_grpc() {
        return PolicyDecision::deny(415, RULE_GRPC, "this route only accepts gRPC requests");
    }
    if route.waf && config.policy.waf.enabled {
        if let Some(rule) = waf_path_rule(head, &config.policy.waf) {
            return PolicyDecision::deny(403, &rule, "request matched a high-confidence WAF rule");
        }
        if config.policy.waf.inspect_query {
            if let Some(query) = &head.query {
                if let Some(rule) = waf_text_layers_rule(query) {
                    return PolicyDecision::deny(
                        403,
                        &rule,
                        "query matched a high-confidence WAF rule",
                    );
                }
            }
        }
        if config.policy.waf.inspect_headers {
            for header in &head.headers {
                if let Some(rule) = waf_text_layers_rule(&header.value) {
                    return PolicyDecision::deny(
                        403,
                        &rule,
                        "request headers matched a high-confidence WAF rule",
                    );
                }
            }
        }
        if config.policy.waf.inspect_body_text {
            let blobs = body_inspection_blobs(context);
            for blob in blobs {
                if let Some(rule) = waf_bytes_rule(blob) {
                    return PolicyDecision::deny(
                        403,
                        &rule,
                        "body matched a high-confidence WAF rule",
                    );
                }
            }
        }
    }
    if route.dlp && config.policy.dlp.enabled && config.policy.dlp.inspect_request {
        if let Some(rule) = evaluate_dlp_blobs(config, dlp_inspection_blobs(context)) {
            return PolicyDecision::deny(451, rule, "request blocked by data-loss policy");
        }
    }
    PolicyDecision::allow(route)
}

pub fn evaluate_response_dlp(
    config: &AppConfig,
    route: &RouteConfig,
    body: &[u8],
) -> Option<&'static str> {
    if !config.policy.dlp.enabled || !config.policy.dlp.inspect_response || !route.dlp {
        return None;
    }
    evaluate_dlp_blobs(config, [body])
}

pub fn evaluate_response_dlp_blobs(
    config: &AppConfig,
    route: &RouteConfig,
    blobs: &[Vec<u8>],
) -> Option<&'static str> {
    if !config.policy.dlp.enabled || !config.policy.dlp.inspect_response || !route.dlp {
        return None;
    }
    evaluate_dlp_blobs(config, blobs.iter().map(Vec::as_slice))
}

pub fn evaluate_response_header_dlp(
    config: &AppConfig,
    route: &RouteConfig,
    headers: &[HeaderField],
) -> Option<&'static str> {
    if !config.policy.dlp.enabled || !config.policy.dlp.inspect_response || !route.dlp {
        return None;
    }
    evaluate_dlp_blobs(config, headers.iter().map(|header| header.value.as_bytes()))
}

pub fn evaluate_response_trailers_dlp(
    config: &AppConfig,
    route: &RouteConfig,
    trailers: &[HeaderField],
) -> Option<&'static str> {
    if !config.policy.dlp.enabled || !config.policy.dlp.inspect_response || !route.dlp {
        return None;
    }
    evaluate_dlp_blobs(
        config,
        trailers.iter().map(|trailer| trailer.value.as_bytes()),
    )
}

pub fn evaluate_request_dlp_blobs(
    config: &AppConfig,
    route: &RouteConfig,
    blobs: &[Vec<u8>],
) -> Option<&'static str> {
    if !config.policy.dlp.enabled || !config.policy.dlp.inspect_request || !route.dlp {
        return None;
    }
    evaluate_dlp_blobs(config, blobs.iter().map(Vec::as_slice))
}

pub fn select_route(config: &AppConfig, head: &RequestHead) -> Option<RouteConfig> {
    let mut selected: Option<&RouteConfig> = None;
    for route in &config.routes {
        if let Some(host) = &route.host {
            if !host.eq_ignore_ascii_case(&head.host) {
                continue;
            }
        }
        if !head.path.starts_with(&route.path_prefix) {
            continue;
        }
        if !route.methods.is_empty() && !route.methods.iter().any(|method| method == &head.method) {
            continue;
        }
        match selected {
            Some(current) if current.path_prefix.len() >= route.path_prefix.len() => {}
            _ => selected = Some(route),
        }
    }
    selected.cloned()
}

pub fn waf_path_rule(head: &RequestHead, config: &WafConfig) -> Option<String> {
    let decoded_path = match percent_decode_strict(&head.path) {
        Ok(value) => value,
        Err(()) => return Some(RULE_TARGET.to_string()),
    };
    let lower = decoded_path.to_ascii_lowercase();
    if lower.contains('\0')
        || lower.contains('\\')
        || lower
            .split('/')
            .any(|segment| segment == ".." || segment == "." || segment.is_empty() && false)
    {
        return Some(RULE_TRAVERSAL.to_string());
    }
    if config.deny_scanner_paths {
        const SCANNER_PATHS: &[&str] = &[
            "/.env",
            "/.git",
            "/wp-config.php",
            "/wp-admin",
            "/phpmyadmin",
            "/xmlrpc.php",
            "/server-status",
            "/actuator",
        ];
        if SCANNER_PATHS.iter().any(|prefix| lower.starts_with(prefix)) {
            return Some(RULE_SCANNER.to_string());
        }
    }
    waf_text_rule(&decoded_path)
}

pub fn waf_text_rule(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let compact = lower.split_whitespace().collect::<Vec<_>>().join(" ");
    let sql_compact = strip_sql_block_comments(&compact);
    if (sql_compact.contains("union select")
        || (sql_compact.contains("select ") && sql_compact.contains(" from "))
        || sql_compact.contains("sleep(")
        || sql_compact.contains("benchmark(")
        || sql_compact.contains("information_schema")
        || sql_compact.contains("xp_cmdshell")
        || sql_compact.contains("or 1=1")
        || sql_compact.contains("and 1=1")
        || sql_compact.contains("or '1'='1")
        || sql_compact.contains("or \"1\"=\"1"))
        && !sql_compact.contains("select option")
    {
        return Some(RULE_SQLI.to_string());
    }
    if lower.contains("<script")
        || lower.contains("javascript:")
        || lower.contains("onerror=")
        || lower.contains("onload=")
        || lower.contains("srcdoc=")
        || lower.contains("<iframe")
    {
        return Some(RULE_XSS.to_string());
    }
    if command_injection(&lower) {
        return Some(RULE_COMMAND.to_string());
    }
    if lower.contains("${jndi:") {
        return Some(RULE_LOG4J.to_string());
    }
    if ["sqlmap", "nikto", "acunetix", "nessus", "masscan", "nmap"]
        .iter()
        .any(|agent| lower.contains(agent))
    {
        return Some(RULE_SCANNER.to_string());
    }
    None
}

fn strip_sql_block_comments(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"/*") {
            if let Some(end) = bytes[index + 2..]
                .windows(2)
                .position(|window| window == b"*/")
            {
                output.push(b' ');
                index += 2 + end + 2;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

pub fn waf_text_layers_rule(value: &str) -> Option<String> {
    let mut current = value.to_string();
    for depth in 0..=WAF_MAX_DECODE_DEPTH {
        if let Some(rule) = waf_text_rule(&current) {
            return Some(rule);
        }
        if let Some(rule) = waf_base64_rule(&current) {
            return Some(rule);
        }
        if depth == WAF_MAX_DECODE_DEPTH {
            break;
        }
        let decoded = decode_embedded_text(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }
    None
}

fn waf_bytes_rule(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let mut start: usize = 0;
    loop {
        let end = start.saturating_add(WAF_SCAN_WINDOW_BYTES).min(bytes.len());
        let text = String::from_utf8_lossy(&bytes[start..end]);
        if let Some(rule) = waf_text_layers_rule(&text) {
            return Some(rule);
        }
        if end == bytes.len() {
            return None;
        }
        start = end.saturating_sub(WAF_SCAN_OVERLAP_BYTES);
    }
}

fn decode_embedded_text(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 5 < bytes.len() && bytes[index + 1] == b'u' {
                if let (Some(high), Some(mid), Some(low), Some(least)) = (
                    hex_value(bytes[index + 2]),
                    hex_value(bytes[index + 3]),
                    hex_value(bytes[index + 4]),
                    hex_value(bytes[index + 5]),
                ) {
                    let code = ((high as u32) << 12)
                        | ((mid as u32) << 8)
                        | ((low as u32) << 4)
                        | least as u32;
                    if let Some(character) = char::from_u32(code) {
                        push_character(&mut output, character);
                        index += 6;
                        continue;
                    }
                }
            }
            if index + 2 < bytes.len() {
                if let (Some(high), Some(low)) =
                    (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
                {
                    output.push((high << 4) | low);
                    index += 3;
                    continue;
                }
            }
        }
        if bytes[index] == b'\\' && index + 1 < bytes.len() {
            if bytes[index + 1] == b'u' && index + 5 < bytes.len() {
                if let (Some(high), Some(mid), Some(low), Some(least)) = (
                    hex_value(bytes[index + 2]),
                    hex_value(bytes[index + 3]),
                    hex_value(bytes[index + 4]),
                    hex_value(bytes[index + 5]),
                ) {
                    let code = ((high as u32) << 12)
                        | ((mid as u32) << 8)
                        | ((low as u32) << 4)
                        | least as u32;
                    if let Some(character) = char::from_u32(code) {
                        push_character(&mut output, character);
                        index += 6;
                        continue;
                    }
                }
            }
            if bytes[index + 1] == b'x' && index + 3 < bytes.len() {
                if let (Some(high), Some(low)) =
                    (hex_value(bytes[index + 2]), hex_value(bytes[index + 3]))
                {
                    output.push((high << 4) | low);
                    index += 4;
                    continue;
                }
            }
        }
        if bytes[index] == b'&' {
            if let Some((decoded, consumed)) = decode_html_entity(&value[index..]) {
                push_character(&mut output, decoded);
                index += consumed;
                continue;
            }
        }
        if bytes[index] == b'+' {
            output.push(b' ');
            index += 1;
            continue;
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn push_character(output: &mut Vec<u8>, character: char) {
    let mut buffer = [0_u8; 4];
    output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
}

fn decode_html_entity(value: &str) -> Option<(char, usize)> {
    let named = [
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&apos;", '\''),
        ("&amp;", '&'),
    ];
    for (entity, decoded) in named {
        if value.starts_with(entity) {
            return Some((decoded, entity.len()));
        }
    }
    let end = value.find(';')?;
    if !value.starts_with("&#") || end <= 2 || end > 12 {
        return None;
    }
    let digits = &value[2..end];
    let code = if let Some(hex) = digits
        .strip_prefix('x')
        .or_else(|| digits.strip_prefix('X'))
    {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        digits.parse::<u32>().ok()?
    };
    Some((char::from_u32(code)?, end + 1))
}

struct WafDecodeBudget {
    candidates_remaining: usize,
    decoded_bytes_remaining: usize,
    exhausted: bool,
}

impl WafDecodeBudget {
    fn new() -> Self {
        Self {
            candidates_remaining: WAF_MAX_BASE64_CANDIDATES,
            decoded_bytes_remaining: WAF_MAX_DECODED_BYTES,
            exhausted: false,
        }
    }

    fn claim_candidate(&mut self) -> bool {
        if self.exhausted {
            return false;
        }
        if self.candidates_remaining == 0 {
            self.exhausted = true;
            return false;
        }
        self.candidates_remaining -= 1;
        true
    }

    fn claim_decoded(&mut self, bytes: usize) -> bool {
        if self.exhausted {
            return false;
        }
        let Some(remaining) = self.decoded_bytes_remaining.checked_sub(bytes) else {
            self.exhausted = true;
            return false;
        };
        self.decoded_bytes_remaining = remaining;
        true
    }
}

fn waf_base64_rule(value: &str) -> Option<String> {
    let mut budget = WafDecodeBudget::new();
    scan_waf_base64(value, 0, &mut budget)
}

fn scan_waf_base64(value: &str, depth: usize, budget: &mut WafDecodeBudget) -> Option<String> {
    if budget.exhausted {
        return Some(RULE_WAF_AMBIGUOUS_ENCODING.to_string());
    }
    for token in value.split(is_not_base64_character) {
        if token.len() < 24 && !base64_token_shape(token) {
            continue;
        }
        if token.len() > WAF_MAX_BASE64_INPUT_BYTES && base64_token_shape(token) {
            return Some(RULE_WAF_AMBIGUOUS_ENCODING.to_string());
        }
        if !plausible_waf_base64_token(token) {
            continue;
        }
        if depth >= WAF_MAX_DECODE_DEPTH {
            return Some(RULE_WAF_AMBIGUOUS_ENCODING.to_string());
        }
        if !budget.claim_candidate() {
            return Some(RULE_WAF_AMBIGUOUS_ENCODING.to_string());
        }
        let Some(decoded) = decode_base64_candidate(token) else {
            continue;
        };
        if decoded.len() < DLP_MIN_DECODED_BYTES || !looks_textual(&decoded) {
            continue;
        }
        if !budget.claim_decoded(decoded.len()) {
            return Some(RULE_WAF_AMBIGUOUS_ENCODING.to_string());
        }
        let decoded_text = String::from_utf8_lossy(&decoded);
        if let Some(rule) = waf_text_rule(&decoded_text) {
            return Some(rule);
        }
        if let Some(rule) = scan_waf_base64(&decoded_text, depth + 1, budget) {
            return Some(rule);
        }
    }

    let compact = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if compact.len() != value.len() && plausible_waf_base64_token(&compact) {
        if depth >= WAF_MAX_DECODE_DEPTH {
            return Some(RULE_WAF_AMBIGUOUS_ENCODING.to_string());
        }
        if !budget.claim_candidate() {
            return Some(RULE_WAF_AMBIGUOUS_ENCODING.to_string());
        }
        if let Some(decoded) = decode_base64_candidate(&compact) {
            if decoded.len() >= DLP_MIN_DECODED_BYTES && looks_textual(&decoded) {
                if !budget.claim_decoded(decoded.len()) {
                    return Some(RULE_WAF_AMBIGUOUS_ENCODING.to_string());
                }
                let decoded_text = String::from_utf8_lossy(&decoded);
                if let Some(rule) = waf_text_rule(&decoded_text) {
                    return Some(rule);
                }
                if let Some(rule) = scan_waf_base64(&decoded_text, depth + 1, budget) {
                    return Some(rule);
                }
            }
        }
    }
    if budget.exhausted {
        Some(RULE_WAF_AMBIGUOUS_ENCODING.to_string())
    } else {
        None
    }
}

fn plausible_waf_base64_token(token: &str) -> bool {
    (24..=WAF_MAX_BASE64_INPUT_BYTES).contains(&token.len()) && base64_token_shape(token)
}

fn command_injection(value: &str) -> bool {
    let commands = [
        "cat",
        "curl",
        "wget",
        "bash",
        "sh",
        "powershell",
        "cmd",
        "nc",
        "netcat",
    ];
    for separator in [";", "||", "&&"] {
        for part in value.split(separator).skip(1) {
            let command = part.trim_start();
            if commands
                .iter()
                .any(|name| command == *name || command.starts_with(&format!("{name} ")))
            {
                return true;
            }
        }
    }
    value.contains("$(") || (value.matches('`').count() >= 2)
}

pub fn is_textual_content_type(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return false;
    };
    let mime = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    mime.starts_with("text/")
        || matches!(
            mime.as_str(),
            "application/json"
                | "application/x-www-form-urlencoded"
                | "application/xml"
                | "application/graphql"
                | "application/soap+xml"
        )
        || mime.ends_with("+json")
        || mime.ends_with("+xml")
}

#[allow(clippy::result_unit_err)]
pub fn percent_decode_strict(value: &str) -> std::result::Result<String, ()> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(());
            }
            let high = hex_value(bytes[index + 1]).ok_or(())?;
            let low = hex_value(bytes[index + 2]).ok_or(())?;
            let decoded = (high << 4) | low;
            if decoded == 0 {
                return Err(());
            }
            output.push(decoded);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| ())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn contains_high_entropy_secret(value: &str) -> bool {
    let mut token_start = None;
    for (index, character) in value
        .char_indices()
        .chain(std::iter::once((value.len(), '\0')))
    {
        if character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '-' | '_') {
            token_start.get_or_insert(index);
            continue;
        }
        let Some(start) = token_start.take() else {
            continue;
        };
        let token = &value[start..index];
        let context_start = start.saturating_sub(64);
        let context_end = index.saturating_add(32).min(value.len());
        let context = value[context_start..context_end].to_ascii_lowercase();
        if high_entropy_token(token, &context) {
            return true;
        }
    }
    false
}

fn high_entropy_token(token: &str, context: &str) -> bool {
    let contextual = [
        "secret",
        "token",
        "api_key",
        "apikey",
        "password",
        "passwd",
        "credential",
        "private_key",
        "access_key",
        "client_secret",
        "authorization",
    ]
    .iter()
    .any(|keyword| context.contains(keyword));
    let hexadecimal = token.bytes().all(|byte| byte.is_ascii_hexdigit());
    if hexadecimal && (!contextual || token.len() < 48) {
        return false;
    }
    let minimum_length = if contextual { 32 } else { 64 };
    if !(minimum_length..=4096).contains(&token.len())
        || encoded_media_context(context)
        || looks_like_encoded_media(token)
    {
        return false;
    }
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    for byte in token.bytes() {
        has_lower |= byte.is_ascii_lowercase();
        has_upper |= byte.is_ascii_uppercase();
        has_digit |= byte.is_ascii_digit();
    }
    has_digit
        && if hexadecimal {
            has_lower || has_upper
        } else {
            has_lower && has_upper
        }
        && shannon_entropy(token.as_bytes())
            >= if hexadecimal {
                3.5
            } else if contextual {
                4.5
            } else {
                5.0
            }
}

fn encoded_media_context(context: &str) -> bool {
    [
        "data:image/",
        "data:application/pdf",
        "data:font/",
        "data:application/octet-stream",
    ]
    .iter()
    .any(|marker| context.contains(marker))
}

fn looks_like_encoded_media(token: &str) -> bool {
    let Some(decoded) = decode_base64_candidate(token) else {
        return false;
    };
    let bytes = decoded.as_slice();
    bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(b"\xff\xd8\xff")
        || bytes.starts_with(b"GIF87a")
        || bytes.starts_with(b"GIF89a")
        || bytes.starts_with(b"%PDF-")
        || bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"\x1f\x8b")
        || bytes.starts_with(b"7z\xbc\xaf\x27\x1c")
        || bytes.starts_with(b"OggS")
        || bytes.starts_with(b"BM")
        || (bytes.len() >= 12 && (bytes.starts_with(b"RIFF") || &bytes[4..8] == b"ftyp"))
}

fn shannon_entropy(value: &[u8]) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = [0_usize; 256];
    for byte in value {
        counts[*byte as usize] = counts[*byte as usize].saturating_add(1);
    }
    let length = value.len() as f64;
    counts
        .iter()
        .filter(|count| **count != 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn contains_aws_key(value: &str) -> bool {
    value.as_bytes().windows(20).any(|window| {
        (&window[..4] == b"AKIA" || &window[..4] == b"ASIA")
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn contains_known_token(value: &str) -> bool {
    for prefix in [
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "glpat-",
        "sk_live_",
        "sk_proj_",
        "sk-proj-",
        "sk-ant-",
        "dckr_pat_",
        "npm_",
        "pypi-",
    ] {
        let mut rest = value;
        while let Some(index) = rest.find(prefix) {
            let candidate = &rest[index + prefix.len()..];
            let length = candidate
                .chars()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || *character == '_' || *character == '-'
                })
                .count();
            if length >= 16 {
                return true;
            }
            rest = &candidate[length..];
        }
    }
    false
}

fn contains_structured_token(value: &str) -> bool {
    contains_jwt(value) || contains_google_api_key(value)
}

fn contains_jwt(value: &str) -> bool {
    for token in value.split(|character: char| {
        !character.is_ascii_alphanumeric() && !matches!(character, '-' | '_' | '.')
    }) {
        if !(40..=16 * 1024).contains(&token.len()) {
            continue;
        }
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if header.len() < 8 || payload.len() < 8 || signature.len() < 8 {
            continue;
        }
        let Some(header_bytes) = decode_base64_candidate(header) else {
            continue;
        };
        if header_bytes.len() > 4096 {
            continue;
        }
        let Ok(header_json) = serde_json::from_slice::<serde_json::Value>(&header_bytes) else {
            continue;
        };
        let Some(header_object) = header_json.as_object() else {
            continue;
        };
        if !header_object.contains_key("alg") && !header_object.contains_key("typ") {
            continue;
        }
        if decode_base64_candidate(payload).is_some_and(|decoded| !decoded.is_empty()) {
            return true;
        }
    }
    false
}

fn contains_google_api_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    const PREFIX: &[u8] = b"AIza";
    const TOTAL_LENGTH: usize = 39;
    if bytes.len() < TOTAL_LENGTH {
        return false;
    }
    for index in 0..=bytes.len() - TOTAL_LENGTH {
        if &bytes[index..index + PREFIX.len()] != PREFIX {
            continue;
        }
        let end = index + TOTAL_LENGTH;
        if index > 0 && is_token_character(bytes[index - 1]) {
            continue;
        }
        if end < bytes.len() && is_token_character(bytes[end]) {
            continue;
        }
        if bytes[index + PREFIX.len()..end]
            .iter()
            .all(|byte| is_token_character(*byte))
        {
            return true;
        }
    }
    false
}

fn is_token_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn body_inspection_blobs<'a>(context: &'a RequestContext<'_>) -> Vec<&'a [u8]> {
    let mut blobs = match context.inspected_body {
        Some(inspected) if !inspected.blobs.is_empty() => {
            inspected.blobs.iter().map(Vec::as_slice).collect()
        }
        _ => vec![context.body],
    };
    blobs.extend(
        context
            .trailers
            .iter()
            .map(|trailer| trailer.value.as_bytes()),
    );
    blobs
}

fn dlp_inspection_blobs<'a>(context: &'a RequestContext<'_>) -> Vec<&'a [u8]> {
    let mut blobs = body_inspection_blobs(context);
    if let Some(query) = context.head.query.as_deref() {
        blobs.push(query.as_bytes());
    }
    blobs.extend(
        context
            .head
            .headers
            .iter()
            .map(|header| header.value.as_bytes()),
    );
    blobs
}

fn looks_textual(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let printable = bytes
        .iter()
        .filter(|byte| {
            **byte == b'\n' || **byte == b'\r' || **byte == b'\t' || (0x20..=0x7e).contains(*byte)
        })
        .count();
    if printable.saturating_mul(100) >= bytes.len().saturating_mul(85) {
        return true;
    }
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars()
            .all(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
    })
}

fn evaluate_dlp_blobs<'a>(
    config: &AppConfig,
    blobs: impl IntoIterator<Item = &'a [u8]>,
) -> Option<&'static str> {
    let blobs = blobs.into_iter().collect::<Vec<_>>();
    let detect_high_entropy = config.policy.dlp.detect_high_entropy;
    for blob in &blobs {
        if let Some(rule) = detect_secret(blob, detect_high_entropy) {
            return Some(rule);
        }
    }

    let mut budget = DlpDecodeBudget::new(config.limits.max_inspect_decoded_bytes);
    for blob in blobs {
        if let Some(rule) = scan_encoded_secrets(blob, detect_high_entropy, 0, &mut budget) {
            return Some(rule);
        }
    }
    if budget.exhausted {
        return Some(RULE_DLP_AMBIGUOUS_ENCODING);
    }
    None
}

fn detect_secret(bytes: &[u8], detect_high_entropy: bool) -> Option<&'static str> {
    let text = String::from_utf8_lossy(bytes);
    let compact = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if DLP_PRIVATE_KEY_MARKERS
        .iter()
        .any(|marker| compact.contains(marker))
    {
        return Some(RULE_DLP_PRIVATE_KEY);
    }
    if contains_aws_key(&compact) || contains_aws_key(&text) {
        return Some(RULE_DLP_AWS);
    }
    if contains_known_token(&compact) || contains_known_token(&text) {
        return Some(RULE_DLP_TOKEN);
    }
    if contains_structured_token(&compact) || contains_structured_token(&text) {
        return Some(RULE_DLP_TOKEN);
    }
    if detect_high_entropy && looks_textual(bytes) && contains_high_entropy_secret(&text) {
        return Some(RULE_DLP_HIGH_ENTROPY);
    }
    None
}

#[derive(Debug)]
struct DlpDecodeBudget {
    candidates_remaining: usize,
    decoded_bytes_remaining: usize,
    exhausted: bool,
}

impl DlpDecodeBudget {
    fn new(max_decoded_bytes: usize) -> Self {
        Self {
            candidates_remaining: DLP_MAX_DECODE_CANDIDATES,
            decoded_bytes_remaining: max_decoded_bytes,
            exhausted: false,
        }
    }

    fn claim_candidate(&mut self) -> bool {
        if self.exhausted {
            return false;
        }
        if self.candidates_remaining == 0 {
            self.exhausted = true;
            return false;
        }
        self.candidates_remaining -= 1;
        true
    }

    fn claim_decoded(&mut self, bytes: usize) -> bool {
        if self.exhausted {
            return false;
        }
        let Some(remaining) = self.decoded_bytes_remaining.checked_sub(bytes) else {
            self.exhausted = true;
            return false;
        };
        self.decoded_bytes_remaining = remaining;
        true
    }
}

impl Default for DlpDecodeBudget {
    fn default() -> Self {
        Self::new(16 * 1024 * 1024)
    }
}

fn scan_encoded_secrets(
    bytes: &[u8],
    detect_high_entropy: bool,
    depth: usize,
    budget: &mut DlpDecodeBudget,
) -> Option<&'static str> {
    if budget.exhausted {
        return Some(RULE_DLP_AMBIGUOUS_ENCODING);
    }
    if let Some(rule) = detect_secret(bytes, detect_high_entropy) {
        return Some(rule);
    }
    if !looks_textual(bytes) {
        return None;
    }

    let text = String::from_utf8_lossy(bytes);
    if depth >= DLP_MAX_DECODE_DEPTH {
        if text_has_decodable_candidate(&text) {
            budget.exhausted = true;
            return Some(RULE_DLP_AMBIGUOUS_ENCODING);
        }
        return None;
    }

    for token in text.split(is_not_base64_character) {
        if token.len() > DLP_MAX_DECODE_INPUT_BYTES && base64_token_shape(token) {
            budget.exhausted = true;
            return Some(RULE_DLP_AMBIGUOUS_ENCODING);
        }
        if !plausible_base64_token(token) {
            continue;
        }
        if !budget.claim_candidate() {
            return Some(RULE_DLP_AMBIGUOUS_ENCODING);
        }
        if let Some(decoded) = decode_base64_candidate(token) {
            if let Some(rule) =
                inspect_decoded_candidate(decoded, detect_high_entropy, depth, budget)
            {
                return Some(rule);
            }
        }
    }

    let compact = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if compact.len() != text.len()
        && compact.len() > DLP_MAX_DECODE_INPUT_BYTES
        && base64_token_shape(&compact)
    {
        budget.exhausted = true;
        return Some(RULE_DLP_AMBIGUOUS_ENCODING);
    }
    if compact.len() != text.len() && plausible_base64_token(&compact) {
        if !budget.claim_candidate() {
            return Some(RULE_DLP_AMBIGUOUS_ENCODING);
        }
        if let Some(decoded) = decode_base64_candidate(&compact) {
            if let Some(rule) =
                inspect_decoded_candidate(decoded, detect_high_entropy, depth, budget)
            {
                return Some(rule);
            }
        }
    }

    if text.contains('%') && has_valid_percent_escape(&text) {
        if text.len() > DLP_MAX_DECODE_INPUT_BYTES {
            budget.exhausted = true;
            return Some(RULE_DLP_AMBIGUOUS_ENCODING);
        }
        if !budget.claim_candidate() {
            return Some(RULE_DLP_AMBIGUOUS_ENCODING);
        }
        if let Ok(decoded) = percent_decode_strict(&text) {
            if let Some(rule) =
                inspect_decoded_candidate(decoded.into_bytes(), detect_high_entropy, depth, budget)
            {
                return Some(rule);
            }
        }
    }
    for token in text.split(|character: char| {
        character.is_ascii_whitespace() || matches!(character, '&' | ';' | '"' | '\'' | '<' | '>')
    }) {
        if token == text || !token.contains('%') || !has_valid_percent_escape(token) {
            continue;
        }
        if token.len() > DLP_MAX_DECODE_INPUT_BYTES {
            budget.exhausted = true;
            return Some(RULE_DLP_AMBIGUOUS_ENCODING);
        }
        if !budget.claim_candidate() {
            return Some(RULE_DLP_AMBIGUOUS_ENCODING);
        }
        if let Ok(decoded) = percent_decode_strict(token) {
            if let Some(rule) =
                inspect_decoded_candidate(decoded.into_bytes(), detect_high_entropy, depth, budget)
            {
                return Some(rule);
            }
        }
    }

    for token in text.split(|character: char| !character.is_ascii_hexdigit()) {
        if token.len() < 32 || token.len() % 2 != 0 {
            continue;
        }
        if token.len() > DLP_MAX_DECODE_INPUT_BYTES {
            budget.exhausted = true;
            return Some(RULE_DLP_AMBIGUOUS_ENCODING);
        }
        if !budget.claim_candidate() {
            return Some(RULE_DLP_AMBIGUOUS_ENCODING);
        }
        if let Ok(decoded) = hex::decode(token) {
            if let Some(rule) =
                inspect_decoded_candidate(decoded, detect_high_entropy, depth, budget)
            {
                return Some(rule);
            }
        }
    }

    if budget.exhausted {
        Some(RULE_DLP_AMBIGUOUS_ENCODING)
    } else {
        None
    }
}

fn inspect_decoded_candidate(
    decoded: Vec<u8>,
    detect_high_entropy: bool,
    depth: usize,
    budget: &mut DlpDecodeBudget,
) -> Option<&'static str> {
    if decoded.len() < DLP_MIN_DECODED_BYTES {
        return None;
    }
    if !budget.claim_decoded(decoded.len()) {
        return Some(RULE_DLP_AMBIGUOUS_ENCODING);
    }
    if let Some(rule) = detect_secret(&decoded, detect_high_entropy) {
        return Some(rule);
    }
    scan_encoded_secrets(&decoded, detect_high_entropy, depth + 1, budget)
}

fn is_not_base64_character(character: char) -> bool {
    !character.is_ascii_alphanumeric() && !matches!(character, '+' | '/' | '=' | '-' | '_')
}

fn plausible_base64_token(token: &str) -> bool {
    (DLP_MIN_BASE64_INPUT_BYTES..=DLP_MAX_DECODE_INPUT_BYTES).contains(&token.len())
        && base64_token_shape(token)
}

fn base64_token_shape(token: &str) -> bool {
    let unpadded = token.trim_end_matches('=');
    if unpadded.len() < DLP_MIN_BASE64_INPUT_BYTES
        || token.len() - unpadded.len() > 2
        || unpadded.contains('=')
        || !token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
        })
    {
        return false;
    }
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for byte in token.bytes() {
        has_lower |= byte.is_ascii_lowercase();
        has_upper |= byte.is_ascii_uppercase();
        has_digit |= byte.is_ascii_digit();
        has_symbol |= matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_');
    }
    usize::from(has_lower)
        + usize::from(has_upper)
        + usize::from(has_digit)
        + usize::from(has_symbol)
        >= 2
}

fn has_valid_percent_escape(value: &str) -> bool {
    value.as_bytes().windows(3).any(|window| {
        window[0] == b'%' && hex_value(window[1]).is_some() && hex_value(window[2]).is_some()
    })
}

fn decode_base64_candidate(token: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(token)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(token))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(token))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token))
        .ok()
}

fn text_has_decodable_candidate(text: &str) -> bool {
    if text.split(is_not_base64_character).any(|token| {
        plausible_base64_token(token)
            || (token.len() > DLP_MAX_DECODE_INPUT_BYTES && base64_token_shape(token))
    }) {
        return true;
    }
    let compact = text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    if compact.len() != text.len()
        && (plausible_base64_token(&compact)
            || (compact.len() > DLP_MAX_DECODE_INPUT_BYTES && base64_token_shape(&compact)))
    {
        return true;
    }
    if text.contains('%') && has_valid_percent_escape(text) {
        return true;
    }
    text.split(|character: char| !character.is_ascii_hexdigit())
        .any(|token| token.len() >= 32 && token.len() % 2 == 0)
}

pub fn connection_has_upgrade(value: &BTreeSet<String>) -> bool {
    value.contains("upgrade")
}

pub fn valid_websocket_key(value: &str) -> bool {
    value.len() <= 64
        && base64::engine::general_purpose::STANDARD
            .decode(value)
            .is_ok_and(|decoded| decoded.len() == 16)
}

pub fn header_token_set(value: Option<&str>) -> BTreeSet<String> {
    value.map(header_tokens).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteConfig;
    use crate::http::{HttpVersion, UpgradeRequest};

    fn head(method: &str, target: &str, host: &str) -> RequestHead {
        let (path, query) = crate::http::split_target(target).unwrap();
        RequestHead {
            method: method.to_string(),
            target: target.to_string(),
            path,
            query,
            version: HttpVersion::Http11,
            headers: vec![crate::http::HeaderField {
                name: "host".to_string(),
                value: host.to_string(),
            }],
            host: host.to_string(),
            content_length: None,
            chunked: false,
            connection_tokens: BTreeSet::new(),
            upgrade: None,
        }
    }

    #[test]
    fn dangerous_targets_are_rejected_default() {
        let config = AppConfig::default();
        let request = head("GET", "/.env", "localhost");
        let context = RequestContext {
            head: &request,
            body: b"",
            inspected_body: None,
            trailers: &[],
            banned_rule: None,
            agent_anomalous: false,
            agent_confirmed: false,
        };
        let decision = evaluate_request(&config, &context);
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.rule_ids, vec![RULE_SCANNER.to_string()]);
    }

    #[test]
    fn successful_h1_request_selects_default_route() {
        let config = AppConfig::default();
        let request = head("GET", "/health", "localhost");
        let context = RequestContext {
            head: &request,
            body: b"",
            inspected_body: None,
            trailers: &[],
            banned_rule: None,
            agent_anomalous: false,
            agent_confirmed: false,
        };
        let decision = evaluate_request(&config, &context);
        assert_eq!(decision.action, PolicyAction::Allow);
        assert_eq!(decision.route.unwrap().name, "default");
    }

    #[test]
    fn websocket_is_denied_unless_route_enables_it() {
        let config = AppConfig::default();
        let mut request = head("GET", "/socket", "localhost");
        request.upgrade = Some(UpgradeRequest {
            websocket_key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            version: "13".to_string(),
            origin: None,
            subprotocols: Vec::new(),
            extensions: None,
        });
        let context = RequestContext {
            head: &request,
            body: b"",
            inspected_body: None,
            trailers: &[],
            banned_rule: None,
            agent_anomalous: false,
            agent_confirmed: false,
        };
        assert_eq!(
            evaluate_request(&config, &context).rule_ids,
            vec![RULE_UPGRADE.to_string()]
        );
    }

    #[test]
    fn agent_signals_escalate_from_rate_limit_to_deny() {
        let config = AppConfig::default();
        let request = head("GET", "/health", "localhost");
        let anomalous = RequestContext {
            head: &request,
            body: b"",
            inspected_body: None,
            trailers: &[],
            banned_rule: None,
            agent_anomalous: true,
            agent_confirmed: false,
        };
        let decision = evaluate_request(&config, &anomalous);
        assert_eq!(decision.action, PolicyAction::RateLimit);
        assert_eq!(decision.status, 429);
        assert_eq!(decision.rule_ids, vec![RULE_AGENT.to_string()]);

        let confirmed = RequestContext {
            agent_anomalous: false,
            agent_confirmed: true,
            ..anomalous
        };
        let decision = evaluate_request(&config, &confirmed);
        assert_eq!(decision.action, PolicyAction::Deny);
        assert_eq!(decision.status, 403);
        assert_eq!(decision.rule_ids, vec![RULE_AGENT.to_string()]);
    }

    #[test]
    fn dlp_blocks_high_confidence_private_key() {
        let config = AppConfig::default();
        let route = RouteConfig::default();
        assert_eq!(
            evaluate_response_dlp(&config, &route, b"-----BEGIN PRIVATE KEY-----\nAAAA\n"),
            Some(RULE_DLP_PRIVATE_KEY)
        );
    }

    fn dlp_rule(bytes: &[u8]) -> Option<&'static str> {
        evaluate_response_dlp(&AppConfig::default(), &RouteConfig::default(), bytes)
    }

    fn base64_private_key() -> Vec<u8> {
        b"-----BEGIN PRIVATE KEY-----\nAAAA\n".to_vec()
    }

    #[test]
    fn dlp_finds_private_key_after_many_base64_decoys() {
        let mut payload = String::new();
        for index in 0..32 {
            let decoy = format!("decoy-payload-{index:04}");
            payload.push_str(&base64::engine::general_purpose::STANDARD.encode(decoy));
            payload.push(' ');
        }
        payload.push_str(&base64::engine::general_purpose::STANDARD.encode(base64_private_key()));
        assert_eq!(dlp_rule(payload.as_bytes()), Some(RULE_DLP_PRIVATE_KEY));
    }

    #[test]
    fn dlp_detects_private_key_through_common_encodings() {
        let key = base64_private_key();
        let standard = base64::engine::general_purpose::STANDARD.encode(&key);
        let mut url_safe_key = key.clone();
        url_safe_key.extend_from_slice(&[0xfb, 0xff, 0x00, 0x10]);
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url_safe_key);
        assert!(url_safe.contains('-') || url_safe.contains('_'));
        let wrapped = standard
            .as_bytes()
            .chunks(16)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(" \r\n");
        let percent = key
            .iter()
            .map(|byte| format!("%{byte:02X}"))
            .collect::<String>();
        let hexadecimal = hex::encode(&key);
        let cases = [
            ("standard base64", standard),
            ("url-safe base64 without padding", url_safe),
            ("whitespace-wrapped base64", wrapped),
            ("percent encoding", percent),
            ("hexadecimal", hexadecimal),
        ];
        for (label, payload) in cases {
            assert_eq!(
                dlp_rule(payload.as_bytes()),
                Some(RULE_DLP_PRIVATE_KEY),
                "{label} was not inspected"
            );
        }
    }

    #[test]
    fn dlp_nested_encoding_is_bounded_and_fails_closed() {
        let key = base64_private_key();
        let once = base64::engine::general_purpose::STANDARD.encode(key);
        let twice = base64::engine::general_purpose::STANDARD.encode(once);
        let three_times = base64::engine::general_purpose::STANDARD.encode(&twice);
        let four_times = base64::engine::general_purpose::STANDARD.encode(three_times);
        assert_eq!(dlp_rule(twice.as_bytes()), Some(RULE_DLP_PRIVATE_KEY));
        assert_eq!(
            dlp_rule(four_times.as_bytes()),
            Some(RULE_DLP_AMBIGUOUS_ENCODING)
        );
    }

    #[test]
    fn dlp_decode_budget_and_candidate_cap_fail_closed() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(base64_private_key());
        let mut small_budget = AppConfig::default();
        small_budget.limits.max_inspect_decoded_bytes = 16;
        assert_eq!(
            evaluate_response_dlp(&small_budget, &RouteConfig::default(), encoded.as_bytes()),
            Some(RULE_DLP_AMBIGUOUS_ENCODING)
        );

        let mut payload = String::new();
        for index in 0..(DLP_MAX_DECODE_CANDIDATES + 8) {
            let decoy = format!("decoy-payload-{index:04}");
            payload.push_str(&base64::engine::general_purpose::STANDARD.encode(decoy));
            payload.push(' ');
        }
        payload.push_str(&encoded);
        assert_eq!(
            dlp_rule(payload.as_bytes()),
            Some(RULE_DLP_AMBIGUOUS_ENCODING)
        );
    }

    #[test]
    fn dlp_oversized_base64_token_fails_closed() {
        let payload = "A1".repeat(DLP_MAX_DECODE_INPUT_BYTES / 2 + 16);
        assert_eq!(
            dlp_rule(payload.as_bytes()),
            Some(RULE_DLP_AMBIGUOUS_ENCODING)
        );
    }

    #[test]
    fn dlp_does_not_flag_benign_text_or_binary() {
        let text = br#"{"message":"ordinary request","url":"https://example.test/path/items","trace_id":"123e4567-e89b-12d3-a456-426614174000"}"#;
        assert_eq!(dlp_rule(text), None);
        let ordinary_base64 = base64::engine::general_purpose::STANDARD
            .encode(b"this is an ordinary message, not a secret");
        assert_eq!(dlp_rule(ordinary_base64.as_bytes()), None);
        let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\xff\xd8\xff\xe0\x00\x10JFIF";
        assert_eq!(dlp_rule(png), None);
    }

    #[test]
    fn dlp_high_entropy_detection_is_enabled_without_flagging_encoded_media() {
        let secret = base64::engine::general_purpose::STANDARD.encode(
            (0_u8..48)
                .map(|index| index.wrapping_mul(73) ^ 0x5a)
                .collect::<Vec<_>>(),
        );
        assert_eq!(secret.len(), 64);
        assert_eq!(dlp_rule(secret.as_bytes()), Some(RULE_DLP_HIGH_ENTROPY));

        let contextual = base64::engine::general_purpose::STANDARD.encode(
            (0_u8..24)
                .map(|index| index.wrapping_mul(29) ^ 0xa7)
                .collect::<Vec<_>>(),
        );
        let contextual = format!("api_key={contextual}");
        assert_eq!(dlp_rule(contextual.as_bytes()), Some(RULE_DLP_HIGH_ENTROPY));

        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend((0_u8..96).map(|index| index.wrapping_mul(41) ^ 0x3d));
        let encoded_png = base64::engine::general_purpose::STANDARD.encode(png);
        let data_uri = format!("data:image/png;base64,{encoded_png}");
        assert_eq!(dlp_rule(data_uri.as_bytes()), None);

        let hexadecimal = "9f".repeat(48);
        assert_eq!(dlp_rule(hexadecimal.as_bytes()), None);
        let hexadecimal_secret = format!(
            "api_key={}",
            (0_u8..32)
                .map(|index| format!("{:02x}", index.wrapping_mul(73) ^ 0x5a))
                .collect::<String>()
        );
        assert_eq!(
            dlp_rule(hexadecimal_secret.as_bytes()),
            Some(RULE_DLP_HIGH_ENTROPY)
        );
        assert_eq!(
            dlp_rule(b"build 2026.11.01 trace 123e4567-e89b-12d3-a456-426614174000"),
            None
        );
    }

    #[test]
    fn dlp_recognizes_additional_private_key_formats() {
        assert_eq!(
            dlp_rule(b"-----BEGIN DSA PRIVATE KEY-----\nAAAA\n"),
            Some(RULE_DLP_PRIVATE_KEY)
        );
        assert_eq!(
            dlp_rule(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nAAAA\n"),
            Some(RULE_DLP_PRIVATE_KEY)
        );
    }

    #[test]
    fn strict_percent_decode_rejects_null_and_invalid_escapes() {
        assert_eq!(percent_decode_strict("/a%2Fb").unwrap(), "/a/b");
        assert!(percent_decode_strict("/a%00b").is_err());
        assert!(percent_decode_strict("/a%2").is_err());
    }

    #[test]
    fn waf_decodes_query_forms_and_common_obfuscation_layers() {
        assert_eq!(
            waf_text_layers_rule("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E").as_deref(),
            Some(RULE_XSS)
        );
        assert_eq!(
            waf_text_layers_rule("q=%253Cscript%253Ealert(1)%253C%252Fscript%253E").as_deref(),
            Some(RULE_XSS)
        );
        assert_eq!(
            waf_text_layers_rule("q=union+select+password+from+users").as_deref(),
            Some(RULE_SQLI)
        );
        assert_eq!(
            waf_text_layers_rule(r"q=\u003cscript\u003ealert(1)\u003c/script\u003e").as_deref(),
            Some(RULE_XSS)
        );
        assert_eq!(
            waf_text_layers_rule("q=&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E").as_deref(),
            Some(RULE_XSS)
        );
        assert_eq!(
            waf_text_rule("union/**/select password from users").as_deref(),
            Some(RULE_SQLI)
        );
    }

    #[test]
    fn waf_scans_large_binary_and_nested_base64_bodies() {
        let mut large = vec![b'a'; 70 * 1024];
        large.extend_from_slice(b" union select password from users");
        assert_eq!(waf_bytes_rule(&large).as_deref(), Some(RULE_SQLI));

        let binary = b"\x00\x01\x02union select password from users\xff";
        assert_eq!(waf_bytes_rule(binary).as_deref(), Some(RULE_SQLI));

        let payload = b"union select secret from t";
        let once = base64::engine::general_purpose::STANDARD.encode(payload);
        let twice = base64::engine::general_purpose::STANDARD.encode(once.as_bytes());
        assert_eq!(waf_bytes_rule(once.as_bytes()).as_deref(), Some(RULE_SQLI));
        assert_eq!(waf_bytes_rule(twice.as_bytes()).as_deref(), Some(RULE_SQLI));
    }

    #[test]
    fn waf_avoids_obvious_benign_body_false_positives() {
        assert_eq!(waf_bytes_rule(&vec![b'a'; 512 * 1024]), None);
        assert_eq!(
            waf_bytes_rule(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\xff\xd8\xff\xe0"),
            None
        );
        assert_eq!(
            waf_bytes_rule(b"ordinary form text with no database query"),
            None
        );
    }

    #[test]
    fn waf_fails_closed_when_encoded_candidate_budget_is_exhausted() {
        let mut payload = String::new();
        for index in 0..(WAF_MAX_BASE64_CANDIDATES + 8) {
            let decoy = format!("ordinary encoded text payload {index:04}");
            payload.push_str(&base64::engine::general_purpose::STANDARD.encode(decoy));
            payload.push(' ');
        }
        assert_eq!(
            waf_base64_rule(&payload).as_deref(),
            Some(RULE_WAF_AMBIGUOUS_ENCODING)
        );
    }

    fn request_dlp_rule(bytes: &[u8]) -> Option<&'static str> {
        let config = AppConfig::default();
        let route = RouteConfig::default();
        evaluate_request_dlp_blobs(&config, &route, &[bytes.to_vec()])
    }

    #[test]
    fn dlp_recognizes_jwt_and_google_style_api_key_in_both_directions() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"1234567890","role":"admin"}"#);
        let jwt = format!("Bearer {header}.{payload}.c2lnbmF0dXJlLXZhbHVl");
        assert_eq!(dlp_rule(jwt.as_bytes()), Some(RULE_DLP_TOKEN));
        assert_eq!(request_dlp_rule(jwt.as_bytes()), Some(RULE_DLP_TOKEN));

        let google_key = format!("AIza{}x", "A1".repeat(17));
        assert_eq!(google_key.len(), 39);
        assert_eq!(dlp_rule(google_key.as_bytes()), Some(RULE_DLP_TOKEN));
        assert_eq!(
            request_dlp_rule(google_key.as_bytes()),
            Some(RULE_DLP_TOKEN)
        );
    }

    #[test]
    fn dlp_structured_credentials_do_not_match_benign_lookalikes() {
        assert_eq!(dlp_rule(b"version 1.2.3.4 and build 2026.11.01"), None);
        assert_eq!(dlp_rule(b"AIza-short-placeholder"), None);
        assert_eq!(
            dlp_rule(b"eyJub3QiOiJqd3QifQ.not-a-valid-payload.signature"),
            None
        );
    }
}
