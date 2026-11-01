use std::{net::SocketAddr, sync::Arc, time::Duration};

use sha2::{Digest, Sha256};

use crate::{
    audit::{next_request_id, normalized_path, AuditEvent},
    config::AppConfig,
    error::CoreError,
    h1::normalize_authority,
    http::{HeaderField, HttpVersion, RequestHead, ResponseHead},
    inspect::{inspect_body, InspectedBody},
    policy::{
        evaluate_request, evaluate_response_dlp_blobs, evaluate_response_header_dlp,
        evaluate_response_trailers_dlp, select_route, PolicyAction, PolicyDecision, RequestContext,
        RULE_AGENT, RULE_BAN, RULE_UPGRADE,
    },
    state::AppState,
    tls::TlsConnectionInfo,
    upstream::{build_h1_request, exchange_h1, exchange_h2, UpstreamResponse, UpstreamTarget},
};

pub const RULE_TLS: &str = "HW-NATIVE-TLS-001";
pub const RULE_TRAILER: &str = "HW-NATIVE-TRAILER-001";
pub const RULE_UPSTREAM: &str = "HW-NATIVE-UPSTREAM-001";

#[derive(Debug, Clone)]
pub struct GatewayRequest {
    pub request_id: u64,
    pub head: RequestHead,
    pub body: Vec<u8>,
    pub trailers: Vec<HeaderField>,
    pub peer: SocketAddr,
    pub tls: TlsConnectionInfo,
    pub secure_transport: bool,
}

impl GatewayRequest {
    pub fn new(
        head: RequestHead,
        body: Vec<u8>,
        trailers: Vec<HeaderField>,
        peer: SocketAddr,
        tls: TlsConnectionInfo,
    ) -> Self {
        let secure_transport = tls.version.is_some()
            || matches!(head.version, HttpVersion::Http2 | HttpVersion::Http3);
        Self {
            request_id: next_request_id(),
            head,
            body,
            trailers,
            peer,
            tls,
            secure_transport,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GatewayResponse {
    pub head: ResponseHead,
    pub body: Vec<u8>,
    pub trailers: Vec<HeaderField>,
}

impl GatewayResponse {
    pub fn synthetic(version: HttpVersion, status: u16, rule: &str, detail: &str) -> Self {
        let body = serde_json::json!({
            "error": if status >= 500 { "request could not be completed" } else { "request rejected" },
            "rule": rule,
            "detail": detail.chars().take(200).collect::<String>(),
        })
        .to_string()
        .into_bytes();
        let reason = http::StatusCode::from_u16(status)
            .ok()
            .and_then(|value| value.canonical_reason())
            .unwrap_or("Error")
            .to_string();
        let mut headers = vec![
            HeaderField {
                name: "content-type".to_string(),
                value: "application/json; charset=utf-8".to_string(),
            },
            HeaderField {
                name: "cache-control".to_string(),
                value: "no-store".to_string(),
            },
            HeaderField {
                name: "x-content-type-options".to_string(),
                value: "nosniff".to_string(),
            },
        ];
        if status == 429 {
            headers.push(HeaderField {
                name: "retry-after".to_string(),
                value: "60".to_string(),
            });
            headers.push(HeaderField {
                name: "x-ratelimit-policy".to_string(),
                value: "highwall-automation-budget".to_string(),
            });
        }
        Self {
            head: ResponseHead {
                version,
                status,
                reason,
                headers,
                content_length: Some(body.len() as u64),
                chunked: false,
                connection_close: status >= 500,
            },
            body,
            trailers: Vec::new(),
        }
    }

    pub fn with_ban_headers(mut self, remaining: Duration) -> Self {
        let retry_after = remaining.as_secs().max(1);
        self.head.headers.push(HeaderField {
            name: "retry-after".to_string(),
            value: retry_after.to_string(),
        });
        self.head.headers.push(HeaderField {
            name: "x-ratelimit-policy".to_string(),
            value: "highwall-source-ban".to_string(),
        });
        self.head.connection_close = true;
        self
    }
}

pub async fn process_request(request: GatewayRequest, state: Arc<AppState>) -> GatewayResponse {
    let path = normalized_path(&request.head.target);
    let route = select_route(&state.config, &request.head);
    let route_name = route
        .as_ref()
        .map(|value| value.name.clone())
        .unwrap_or_else(|| "unmatched".to_string());

    if let Err(error) = state.audit.require_available() {
        return reject_early(
            &state,
            &request,
            &path,
            &route_name,
            503,
            "HW-NATIVE-AUDIT-001",
            &error.to_string(),
        );
    }

    if request.secure_transport && !sni_host_matches(&state.config, &request.tls, &request.head) {
        return reject_early(
            &state,
            &request,
            &path,
            &route_name,
            421,
            RULE_TLS,
            "TLS server name does not match the request authority",
        );
    }

    let inspect_required = route.as_ref().is_some_and(|value| {
        (value.waf && state.config.policy.waf.enabled && state.config.policy.waf.inspect_body_text)
            || (value.dlp
                && state.config.policy.dlp.enabled
                && state.config.policy.dlp.inspect_request)
            || (value.grpc && request.head.is_grpc())
    });
    let inspected: Option<InspectedBody> = if inspect_required {
        match inspect_body(
            &request.head.headers,
            &request.body,
            request.head.is_grpc(),
            &state.config.limits,
            state.config.policy.inspect_compressed_bodies,
        ) {
            Ok(value) => Some(value),
            Err(error) => {
                return reject_early(
                    &state,
                    &request,
                    &path,
                    &route_name,
                    error.status,
                    error.rule,
                    &error.detail,
                );
            }
        }
    } else {
        None
    };

    let banned = state.bans.is_banned(request.peer.ip());
    let user_agent_hash = request.head.header("user-agent").map(hash_text);
    let agent = state.agent.observe(
        request.peer.ip(),
        hash_text(&request.head.path),
        hash_text(&request.head.method),
        user_agent_hash,
    );
    let decision = evaluate_request(
        &state.config,
        &RequestContext {
            head: &request.head,
            body: &request.body,
            inspected_body: inspected.as_ref(),
            trailers: &request.trailers,
            banned_rule: banned,
            agent_anomalous: agent.anomalous,
            agent_confirmed: agent.confirmed,
        },
    );
    let route_name = decision
        .route
        .as_ref()
        .map(|value| value.name.clone())
        .unwrap_or(route_name);

    let mut accepted = audit_event(&request, &path, &route_name, "accepted", 0);
    accepted.rule_ids = decision.rule_ids.clone();
    accepted.bytes_in = request.body.len() as u64;
    if !agent.reasons.is_empty() {
        accepted.detail = Some(format!(
            "agent={:?} score={} requests={} paths={} methods={} user_agents={}",
            agent.reasons,
            agent.score,
            agent.requests,
            agent.distinct_paths,
            agent.distinct_methods,
            agent.user_agent_changes
        ));
    }
    if !state.audit.record(accepted) {
        return GatewayResponse::synthetic(
            request.head.version,
            503,
            "HW-NATIVE-AUDIT-001",
            "audit unavailable",
        );
    }

    if decision.action != PolicyAction::Allow {
        if is_enforcement_rule(&decision) {
            state
                .bans
                .note_violation(request.peer.ip(), first_rule(&decision.rule_ids));
        }
        let mut response = rejection_for_decision(request.head.version, &decision);
        if first_rule(&decision.rule_ids) == RULE_BAN {
            if let Some(remaining) = state.bans.remaining(request.peer.ip()) {
                response = response.with_ban_headers(remaining);
            }
        }
        record_completion(
            &state,
            &request,
            &path,
            &route_name,
            &decision.rule_ids,
            response.head.status,
            request.body.len(),
            response.body.len() as u64,
        );
        return response;
    }

    if !state.rate.check(request.peer.ip()).permit {
        let response = GatewayResponse::synthetic(
            request.head.version,
            429,
            RULE_AGENT,
            "request rate exceeded",
        );
        record_completion(
            &state,
            &request,
            &path,
            &route_name,
            &[RULE_AGENT.to_string()],
            429,
            request.body.len(),
            response.body.len() as u64,
        );
        return response;
    }

    let Some(route) = decision.route.clone() else {
        let response = GatewayResponse::synthetic(
            request.head.version,
            503,
            "HW-NATIVE-ROUTE-001",
            "route unavailable",
        );
        record_completion(
            &state,
            &request,
            &path,
            &route_name,
            &["HW-NATIVE-ROUTE-001".to_string()],
            503,
            request.body.len(),
            response.body.len() as u64,
        );
        return response;
    };

    if !request.trailers.is_empty() && !route.grpc {
        let response = GatewayResponse::synthetic(
            request.head.version,
            400,
            RULE_TRAILER,
            "request trailers require an HTTP/2 gRPC route",
        );
        record_completion(
            &state,
            &request,
            &path,
            &route_name,
            &[RULE_TRAILER.to_string()],
            400,
            request.body.len(),
            response.body.len() as u64,
        );
        return response;
    }

    let target = UpstreamTarget::from_config(&state.config, &route);
    let upstream = if route.grpc {
        let h2_enabled = route
            .upstream
            .as_ref()
            .unwrap_or(&state.config.upstream)
            .h2_for_grpc;
        if !h2_enabled {
            let response = GatewayResponse::synthetic(
                request.head.version,
                503,
                "HW-NATIVE-GRPC-004",
                "gRPC route requires an HTTP/2 upstream",
            );
            record_completion(
                &state,
                &request,
                &path,
                &route_name,
                &["HW-NATIVE-GRPC-004".to_string()],
                503,
                request.body.len(),
                response.body.len() as u64,
            );
            return response;
        }
        let stream = match target.connect(&state.config).await {
            Ok(stream) => stream,
            Err(error) => return upstream_failure(&state, &request, &path, &route_name, error),
        };
        exchange_h2(
            stream,
            &request.head,
            &request.body,
            &request.trailers,
            request.peer,
            request.request_id,
            &target,
            &state.config,
            if request.secure_transport {
                "https"
            } else {
                "http"
            },
        )
        .await
    } else {
        let stream = match target.connect(&state.config).await {
            Ok(stream) => stream,
            Err(error) => return upstream_failure(&state, &request, &path, &route_name, error),
        };
        let raw = build_h1_request(
            &request.head,
            &request.body,
            request.peer,
            request.request_id,
            &target,
            if request.secure_transport {
                "https"
            } else {
                "http"
            },
        );
        match exchange_h1(stream, &raw, &request.head.method, &state.config).await {
            Ok((_reader, head, body)) => Ok(UpstreamResponse {
                head,
                body,
                trailers: Vec::new(),
            }),
            Err(error) => Err(error),
        }
    };

    let upstream = match upstream {
        Ok(response) => response,
        Err(error) => return upstream_failure(&state, &request, &path, &route_name, error),
    };

    if let Some(rule) = evaluate_response_header_dlp(&state.config, &route, &upstream.head.headers)
    {
        return response_dlp_rejection(
            &state,
            &request,
            &path,
            &route_name,
            rule,
            "response headers blocked by data-loss policy",
        );
    }

    let is_grpc = request.head.is_grpc();
    let response_inspection = if is_grpc
        || (route.dlp
            && state.config.policy.dlp.enabled
            && state.config.policy.dlp.inspect_response)
    {
        match inspect_body(
            &upstream.head.headers,
            &upstream.body,
            is_grpc,
            &state.config.limits,
            state.config.policy.inspect_compressed_bodies,
        ) {
            Ok(value) => Some(value),
            Err(error) => {
                return response_dlp_rejection(
                    &state,
                    &request,
                    &path,
                    &route_name,
                    error.rule,
                    "response could not be inspected completely",
                );
            }
        }
    } else {
        None
    };

    if let Some(inspected) = &response_inspection {
        if let Some(rule) = evaluate_response_dlp_blobs(&state.config, &route, &inspected.blobs) {
            return response_dlp_rejection(
                &state,
                &request,
                &path,
                &route_name,
                rule,
                "response blocked by data-loss policy",
            );
        }
    } else if let Some(rule) =
        evaluate_response_dlp_blobs(&state.config, &route, std::slice::from_ref(&upstream.body))
    {
        return response_dlp_rejection(
            &state,
            &request,
            &path,
            &route_name,
            rule,
            "response blocked by data-loss policy",
        );
    }
    if let Some(rule) = evaluate_response_trailers_dlp(&state.config, &route, &upstream.trailers) {
        return response_dlp_rejection(
            &state,
            &request,
            &path,
            &route_name,
            rule,
            "response trailers blocked by data-loss policy",
        );
    }

    let response = GatewayResponse {
        head: upstream.head,
        body: upstream.body,
        trailers: upstream.trailers,
    };
    record_completion(
        &state,
        &request,
        &path,
        &route_name,
        &[],
        response.head.status,
        request.body.len(),
        response.body.len() as u64,
    );
    response
}

fn response_dlp_rejection(
    state: &AppState,
    request: &GatewayRequest,
    path: &str,
    route_name: &str,
    rule: &str,
    detail: &str,
) -> GatewayResponse {
    let banned = rule.starts_with("HW-NATIVE-DLP-")
        && state.bans.note_response_violation(request.peer.ip(), rule);
    let mut response = GatewayResponse::synthetic(request.head.version, 451, rule, detail);
    if banned {
        if let Some(remaining) = state.bans.remaining(request.peer.ip()) {
            response = response.with_ban_headers(remaining);
        }
    }
    record_completion(
        state,
        request,
        path,
        route_name,
        &[rule.to_string()],
        451,
        request.body.len(),
        response.body.len() as u64,
    );
    response
}

pub fn rejection_for_decision(version: HttpVersion, decision: &PolicyDecision) -> GatewayResponse {
    GatewayResponse::synthetic(
        version,
        decision.status,
        first_rule(&decision.rule_ids),
        &decision.reason,
    )
}

pub fn first_rule(rules: &[String]) -> &str {
    rules.first().map(String::as_str).unwrap_or(RULE_AGENT)
}

pub fn is_enforcement_rule(decision: &PolicyDecision) -> bool {
    decision.action == PolicyAction::Deny
        && decision.rule_ids.iter().any(|rule| {
            rule.starts_with("HW-NATIVE-WAF-")
                || rule.starts_with("HW-NATIVE-DLP-")
                || rule.starts_with("HW-NATIVE-WS-")
                || rule.starts_with("HW-NATIVE-GRPC-")
                || rule == RULE_AGENT
                || rule == RULE_UPGRADE
        })
}

pub fn sni_host_matches(config: &AppConfig, tls: &TlsConnectionInfo, head: &RequestHead) -> bool {
    let Some(tls_config) = &config.tls else {
        return true;
    };
    if !tls_config.require_sni_host_match {
        return true;
    }
    let Some(server_name) = tls.server_name.as_deref() else {
        return tls_config.allow_missing_sni;
    };
    let Ok(server_name) = normalize_authority(server_name) else {
        return false;
    };
    server_name.eq_ignore_ascii_case(&head.host)
}

#[allow(clippy::too_many_arguments)]
pub fn record_completion(
    state: &AppState,
    request: &GatewayRequest,
    path: &str,
    route_name: &str,
    rules: &[String],
    status: u16,
    bytes_in: usize,
    bytes_out: u64,
) {
    let mut event = audit_event(
        request,
        path,
        route_name,
        if status < 400 { "allow" } else { "deny" },
        status,
    );
    event.rule_ids = rules.to_vec();
    event.bytes_in = bytes_in as u64;
    event.bytes_out = bytes_out;
    let _ = state.audit.record(event);
}

pub fn record_timeout(
    state: &AppState,
    request: &GatewayRequest,
    path: &str,
    route_name: &str,
    status: u16,
) {
    record_completion(
        state,
        request,
        path,
        route_name,
        &["HW-NATIVE-TIMEOUT-001".to_string()],
        status,
        request.body.len(),
        0,
    );
}

fn reject_early(
    state: &AppState,
    request: &GatewayRequest,
    path: &str,
    route_name: &str,
    status: u16,
    rule: &str,
    detail: &str,
) -> GatewayResponse {
    let response = GatewayResponse::synthetic(request.head.version, status, rule, detail);
    let mut event = audit_event(request, path, route_name, "deny", status);
    event.rule_ids = vec![rule.to_string()];
    event.bytes_in = request.body.len() as u64;
    event.bytes_out = response.body.len() as u64;
    let _ = state.audit.record(event);
    response
}

fn upstream_failure(
    state: &AppState,
    request: &GatewayRequest,
    path: &str,
    route_name: &str,
    error: CoreError,
) -> GatewayResponse {
    let timing_out = error.to_string().contains("timed out");
    let status = if timing_out { 504 } else { 502 };
    let rule = if timing_out {
        "HW-NATIVE-UPSTREAM-003"
    } else {
        "HW-NATIVE-UPSTREAM-002"
    };
    let response = GatewayResponse::synthetic(
        request.head.version,
        status,
        rule,
        if timing_out {
            "upstream timed out"
        } else {
            "upstream request could not be completed"
        },
    );
    record_completion(
        state,
        request,
        path,
        route_name,
        &[rule.to_string()],
        status,
        request.body.len(),
        response.body.len() as u64,
    );
    response
}

fn audit_event(
    request: &GatewayRequest,
    path: &str,
    route_name: &str,
    decision: &str,
    status: u16,
) -> AuditEvent {
    let mut event = AuditEvent::new(
        request.request_id,
        request.peer.to_string(),
        protocol_label(request.head.version),
        &request.head.method,
        path,
        route_name,
        decision,
        status,
    );
    event.tls_server_name = request.tls.server_name.clone();
    event.tls_version = request.tls.version.clone();
    event.alpn = request.tls.alpn.clone();
    event
}

fn protocol_label(version: HttpVersion) -> &'static str {
    match version {
        HttpVersion::Http10 | HttpVersion::Http11 => "h1",
        HttpVersion::Http2 => "h2",
        HttpVersion::Http3 => "h3",
    }
}

pub fn hash_text(value: &str) -> u64 {
    let digest = Sha256::digest(value.as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(action: PolicyAction, status: u16, rule: &str) -> PolicyDecision {
        PolicyDecision {
            action,
            status,
            rule_ids: vec![rule.to_string()],
            reason: "test".to_string(),
            route: None,
        }
    }

    #[test]
    fn rate_limits_are_backpressure_not_ban_evidence() {
        let rate_limited = decision(PolicyAction::RateLimit, 429, RULE_AGENT);
        assert!(!is_enforcement_rule(&rate_limited));

        let denied = decision(PolicyAction::Deny, 403, RULE_AGENT);
        assert!(is_enforcement_rule(&denied));
    }

    #[test]
    fn rate_limit_response_is_observable() {
        let response =
            GatewayResponse::synthetic(HttpVersion::Http11, 429, RULE_AGENT, "slow down");
        assert!(response
            .head
            .headers
            .iter()
            .any(|header| header.name == "retry-after" && header.value == "60"));
        assert!(response
            .head
            .headers
            .iter()
            .any(|header| header.name == "x-ratelimit-policy"));
    }
}
