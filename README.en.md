# HighWall

English | [简体中文](README.md)

[![CI](https://github.com/Fallen-leaves089/highwall/actions/workflows/ci.yml/badge.svg)](https://github.com/Fallen-leaves089/highwall/actions/workflows/ci.yml) [![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

HighWall is a **fail-closed HTTP/1.1 application-layer reverse proxy and security gateway**. It uses only the Python standard library and aims to turn the parsing, policy, resource-limit, and audit decisions most prone to ambiguity at an application entry point into a small, auditable core.

Current version: `0.8.1`. v0.3 expanded the protection goal from response leakage prevention to **confidentiality, integrity, and availability** together; v0.4 added configurable exact-path honeypots, first-hit bans, and bounded delays; v0.5 added built-in honeypot templates and preset groups; v0.6 added configuration generation, effective-value inspection, and local quick deployment; v0.7 tightened path normalization, request-body encoding, response DLP, and audit redaction, and added route-level rate limits and TLS HSTS; v0.8 adds multi-signal attacker fingerprints, persistent marks, two-stage containment, L7 DDoS alerts, and asynchronous webhooks. It is still not a production-grade product that has completed an independent third-party audit.

> **v0.8 focus**: multi-signal attacker correlation, persistent marks after confirmation, a 15-minute confirmed slow window, L7 DDoS alerts, and asynchronous webhooks. See [Enabling threat protection](#enabling-threat-protection) for the rollout sequence and [L7 DDoS alerts and the 5-minute response window](#l7-ddos-alerts-and-the-5-minute-response-window) for the on-call process.

## Contents

- [30-second overview](#30-second-overview)
- [30-second demo](#30-second-demo)
- [What it solves](#what-it-solves)
- [Attacker fingerprints, marks, and slowdown](#attacker-fingerprints-marks-and-slowdown)
- [L7 DDoS alerts and the 5-minute response window](#l7-ddos-alerts-and-the-5-minute-response-window)
- [Enabling threat protection](#enabling-threat-protection)
- [Quick start](#quick-start)
- [Configuration highlights](#configuration-highlights)
- [Troubleshooting](#troubleshooting)
- [Deployment principles](#deployment-principles)
- [Tests and smoke checks](#tests-and-smoke-checks)

## 30-second overview

HighWall puts strict request parsing, default-deny policy, resource limits, audit logging, and response inspection into a small process that uses only the Python standard library. It is designed to sit in front of an application as an auditable L7 layer.

- **Fail-closed**: ambiguous input, invalid configuration, or upstream failure returns an error instead of being silently allowed.
- **No third-party runtime dependencies**: the core proxy uses only the Python standard library, which keeps it easy to audit and deploy.
- **Verifiable**: built-in tests, `highwall check` / `inspect`, a local quickstart, and structured JSONL audit output.

- Good fit: internal services, static sites, admin surfaces, and small APIs that need an extra ingress layer.
- Not a fit: large-scale DDoS scrubbing, WebSocket/HTTP/2 proxying, or replacing application authentication and authorization.

> HighWall is still at `0.8.1` and has not received an independent security audit. Read [What it does not solve](#what-it-does-not-solve) and [Deployment principles](#deployment-principles) before production use.

## 30-second demo

Windows single-machine demo (no second computer, no administrator rights):

```powershell
git clone https://github.com/Fallen-leaves089/highwall.git
cd highwall
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\demo.ps1
```

The script starts a temporary upstream and HighWall on loopback, sends a normal request plus a bad Host, SQL injection, path traversal, honeypot probe, and invalid method, prints the resulting audit events, then stops and cleans up. Output is similar to:

```text
HighWall single-machine demo
  listen:   127.0.0.1:<port>
  upstream: 127.0.0.1:<port>

[PASS] normal       status=200 expected=200
[PASS] bad host     status=403 expected=403
[PASS] sqli         status=403 expected=403
[PASS] traversal    status=400 expected=400
[PASS] honeypot     status=200 expected=200
[PASS] trace        status=405 expected=405

[audit] request_blocked status=403 rule=HW-HOST-1003
[audit] honeypot_hit    status=200 rule=HW-HONEY-env_probe
```

The script exits non-zero if any assertion fails. Add `-KeepRuntime` to retain the temporary runtime directory.

For a persistent local instance, use quickstart (it also starts a demo upstream):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -WithDemoUpstream
```

Or generate a configuration and check it:

```bash
python -m highwall init --upstream http://127.0.0.1:8080 --allowed-host app.internal --output config.json
python -m highwall check -c config.json
python -m highwall serve -c config.json
```

See [Quick start](#quick-start) for all options.

## What it solves

- Strict HTTP/1.x parsing: accepts only origin-form requests with an explicit `Content-Length`, and rejects `Transfer-Encoding`, `TE`, folded headers, duplicate sensitive headers, protocol upgrades, and encoded request bodies. This removes the usual CL.TE / TE.CL request-smuggling surface.
- Three independent default-deny layers: Host, method, and path prefix. Host must exactly match a configured authority.
- After path decoding, checks dot segments, encoded separators, backslashes, control characters, and NFKC normalization. Path parameters, trailing dots, and trailing spaces are rejected by default. Route ACL, method, and read-only decisions all use the same case-insensitive normalized path.
- Conservative application signatures for SQL injection, XSS, path traversal, command injection, JNDI, and SSRF heuristics, with `detect` and `block` modes.
- Every request has absolute header and body deadlines. Upstream connect, individual reads, and the complete upstream exchange each have independent limits.
- Hard limits on concurrent connections, request-line size, header count and size, request body, response body, and memory budget.
- Optional application-layer allow and deny rules by client CIDR. Deny rules take precedence, and an empty configuration preserves compatibility.
- Optional Origin allowlist: once configured, write methods must carry an allowed Origin, and cross-site write requests with `Sec-Fetch-Site: cross-site` are rejected.
- Per-client concurrent connection limits, plus temporary bans for clients that repeatedly trigger protocol or policy errors in a short window.
- Longest-prefix route policies: method subsets, read-only mode, route-level client CIDRs, body limits, dedicated concurrency slots, and per-client token-bucket rate limits.
- Best-effort multi-signal fingerprints from HTTP header shape, the TLS ClientHello when HighWall terminates TLS, and a `/24` or `/64` source prefix. Sensitive header values are reduced to redacted placeholders and never become part of the fingerprint.
- Two-stage containment: `suspected` traffic is first throttled for a 5-minute window; `confirmed` attackers are written to a bounded persistent mark store and slowed for 15 minutes. Tarpit slots are globally and per-actor bounded.
- Aggregates L7 request rate, rejection ratio, connection saturation, TLS handshake failures, and upstream error ratio into `ddos_suspected` / `ddos_escalated` alerts, with a 5-minute response window, recovery events, and asynchronous webhook delivery.
- Configurable exact-path honeypots: built-in templates for common scanning paths return local static decoys and never contact the upstream. A hit creates a dedicated audit event and can immediately ban the source or add a bounded short delay.
- Global or route-level `read_only`: write methods are rejected before reaching the upstream, which is useful for static sites, backup browsing, and separating administrative reads from writes.
- Optional response-integrity pinning for exact `GET` paths: validates the status code and response-body SHA-256. `detect` records a hit; `block` returns 502 without forwarding the replaced content.
- Optional upstream circuit breaker: after repeated connection failures, timeouts, or 5xx responses, requests are rejected briefly; after cooldown, bounded half-open probes verify recovery to prevent failure amplification.
- Global in-flight request limits prevent established connections from occupying all processing threads at once. Route-level concurrency slots protect expensive endpoints.
- Response-side DLP: scans a bounded response-body prefix and response headers for private keys, common cloud, code-hosting, payment, and AI tokens, JWTs, database URI credentials, and common debug-stack leaks. Supports UTF-8, Latin-1, and UTF-16. `Set-Cookie` is excluded by default to avoid false positives on login sessions.
- Forces `Accept-Encoding: identity` toward the upstream and rejects compressed or encoding-ambiguous responses so DLP cannot be bypassed at the compression layer.
- Re-frames upstream responses: rejects duplicate or invalid `Content-Length`, conflicting `Content-Length` and `Transfer-Encoding`, and non-`chunked` upstream `Transfer-Encoding`, then generates a new `Content-Length`.
- Client bypass headers such as `X-Forwarded-*`, `Forwarded`, `X-Original-URL`, and `X-HTTP-Method-Override` do not reach the upstream unchanged.
- Structured JSONL audit records with fixed fields; query strings, cookies, Authorization headers, and request bodies are never logged. Sensitive path segments and path parameters are redacted by default, with hash and explicit exact modes available. Audit files are size-bounded and rotated.
- When TLS is enabled and HSTS is not configured explicitly, adds `Strict-Transport-Security: max-age=31536000` automatically.
- The admin plane listens only on loopback, uses a Bearer token supplied through an environment variable, and exposes health, metrics, and audit-tail endpoints read-only.
- Includes a read-only Windows host-audit script that checks firewall default policy, RPC/SMB/RDP listeners, port proxies, Defender/ASR, backup visibility, and HighWall file ACLs without changing system state.
- Includes `highwall init`, `highwall inspect`, and Windows `scripts/quickstart.ps1`: one command generates a configuration, starts the service, performs acceptance checks, and records state without silently overwriting existing configuration.

## CIA coverage boundaries

| Goal | L7 controls HighWall can provide | Still required elsewhere |
|---|---|---|
| Confidentiality | Host/path/source restrictions, WAF, response DLP, security headers, loopback admin plane | User authentication, key management, disk/memory/loopback protection, least-privilege egress |
| Integrity | Route method allowlists, read-only mode, request-body limits, response SHA-256 pinning, controlled response headers | Upstream authorization, database constraints, file integrity, EDR, immutable backups |
| Availability | Connection/in-flight/route concurrency limits, rate limits, temporary bans, attacker marks, bounded slow slots, L7 DDoS alerts, upstream circuit breaker, timeouts | Bandwidth scrubbing, SYN-flood protection, host capacity, upstream high availability and disaster recovery |

## Attacker fingerprints, marks, and slowdown

The HighWall 0.8 fingerprint is a **multi-signal correlation**, not an identity and not a claim of “the world's most precise fingerprint”:

- HTTP header names, ordering, and stable fields such as User-Agent, Accept, and Sec-Fetch-*;
- the ClientHello observed when HighWall terminates TLS: version, ciphers, extensions, groups, signature algorithms, ALPN, and whether SNI is present;
- the source `/24` (IPv4) or `/64` (IPv6) prefix.

Cookies, Authorization, Proxy-Authorization, Set-Cookie, API keys, and similar secrets participate only as `<redacted>` shape markers. Raw paths, query strings, request bodies, cookie values, and tokens do not enter fingerprints, persistent marks, or alert payloads. TLS fingerprinting is available only when HighWall terminates TLS; if TLS terminates in front of HighWall, only HTTP shape and source-prefix correlation remain available.

Containment has two stages:

1. `suspected`: request rate, path breadth, and policy-violation signals reach the threshold and receive a delay first in `throttle` / `tarpit` mode. The default containment window is `containment_seconds=300` (5 minutes).
2. `confirmed`: reaching `confirm_score`, matching an existing confirmed mark, or remaining suspected for `confirm_after_seconds=300` promotes the actor. HighWall writes `offenders.json` and applies a default `confirmed_containment_seconds=900` (15 minutes) slow window. The mark TTL is `mark_ttl_seconds=86400`.

`mode` may be `monitor` (alert only, no slow path, but confirmed actors are still marked), `throttle` (delay), `tarpit` (slow response), or `block` (429). `tarpit` applies only to confirmed attackers; both per-actor and global slots are bounded, and a full slot returns 429 instead of continuing to occupy threads. Start with `monitor` to observe false positives before switching to `tarpit`.

A slowdown capacity estimate is `T ~= ceil(N / S) * H`. With the default `S=4` per-actor slots and `H=15` seconds, about 80 requests can form a 5-minute window and about 240 requests can form a 15-minute window. `H` comes from `tarpit_hold_seconds` and is capped by `max_tarpit_hold_seconds`; HighWall schedules the final response-body chunk at `H` seconds after the response headers are sent. This is a capacity estimate, not an SLA: rotating `/24` or `/64` sources, TLS/header fingerprints, botnets, or retries after slot exhaustion all change the result. Shared NAT can also cause collateral slowdown.

The mark file contains only derived fingerprints, scores, signals, and an optional client IP (disabled by default). It must live in an ACL-protected data directory. When the admin plane is enabled, inspect marks with:

```powershell
curl.exe -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" http://127.0.0.1:18091/offenders
```

## L7 DDoS alerts and the 5-minute response window

HighWall aggregates five L7 signals: request rate, rejection ratio, connection saturation, TLS handshake-failure count, and upstream error ratio. By default at least two signals must agree before it emits `ddos_suspected`; after 300 seconds it escalates to `ddos_escalated`, and after 30 seconds without signals it emits `ddos_recovered`. The `containment_window_seconds=300` field in the alert payload is a recommended 5-minute response window, not an automatic scrubbing guarantee.

Webhook alerts use a bounded asynchronous queue, retry once, and drop with a counter when the queue is full without blocking request threads. HTTPS is required by default; redirects and credentials embedded in the URL are rejected:

```powershell
$env:HIGHWALL_ALERT_WEBHOOK = "https://alerts.example.com/highwall"
$env:HIGHWALL_ALERT_TOKEN = "<16+ random characters>"
```

Route DDoS alerts to a NOC or on-call system. During the 5-minute window, confirm CDN/scrubbing status, check upstream capacity and errors, preserve audit evidence, and enable edge rate limiting according to the incident plan. **Bandwidth-based L3/L4 DDoS must be handled by the carrier or scrubbing provider**; HighWall may become unreachable before its alert is delivered, so configure an external heartbeat that is independent of this host. Never expose the admin plane to the public internet just to read alerts.

### Alert events and first actions

| Event | Meaning | First on-call action |
|---|---|---|
| `threat_suspected` | One attacker fingerprint crossed the suspicion threshold | Check the source prefix, shared NAT, normal automation, and audit events; watch for escalation |
| `threat_confirmed` | The actor crossed the confirmation threshold or matched a persisted mark | Preserve evidence, verify that slow lanes are not exhausting normal capacity, then decide whether an operator ban is needed |
| `ddos_suspected` | At least two L7 signals are abnormal at the same time | Notify on-call immediately and start the 5-minute response window; do not wait for automatic scrubbing |
| `ddos_escalated` | The anomaly has lasted for 300 seconds | Escalate to the NOC, network team, or scrubbing provider; check CDN, upstream capacity, and edge limits |
| `ddos_recovered` | L7 signals have returned below threshold | Observe and preserve evidence; do not immediately undo every manual control |

### 5-minute response checklist

- **0-1 minutes**: Confirm the alert time, affected hostnames, and source; avoid restarting HighWall before collecting evidence and slow-lane state.
- **1-3 minutes**: Check CDN/scrubbing status, upstream 5xx and timeouts, connection saturation, TLS handshake failures, and audit events.
- **3-5 minutes**: Apply the incident plan for edge rate limiting or scrubbing, preserve audit and metrics, and notify the business owner.
- **Still `ddos_escalated` after 5 minutes**: Escalate to network, carrier, or scrubbing teams. HighWall is not a bandwidth scrubber or an upstream capacity expansion.

### Webhook payload example

The values below are illustrative, not fixed. By default the payload omits the client IP, raw paths, cookies, Authorization, and request bodies:

```json
{
  "schema": "highwall.alert.v1",
  "event": "ddos_escalated",
  "severity": "critical",
  "layer": "L7",
  "signals": {
    "request_rate": 812.4,
    "connection_saturation": 0.93
  },
  "action": "escalate_to_noc_and_check_edge_scrubbing",
  "containment_window_seconds": 300,
  "recommended_actions": [
    "notify_noc",
    "check_edge_scrubbing",
    "verify_upstream_capacity",
    "preserve_audit_logs"
  ]
}
```

## Enabling threat protection

`highwall init` and `scripts/quickstart.ps1` disable `threat_detection`, `ddos_detection`, and `alerting` by default so a new deployment does not throttle or alert before normal traffic has been reviewed. `config.example.json` sets threat and DDoS detection to `true` to demonstrate the fields, but still leaves `alerting.enabled` as `false`; do not copy it directly as a production configuration.

Recommended rollout:

1. Start with `mode=monitor` and observe `threat_suspected` / `threat_confirmed` to verify shared NAT, probes, and normal automation.
2. Confirm `per_actor_tarpit_slots`, `global_tarpit_slots`, and `tarpit_hold_seconds` fit the connection and thread budget, then move to `mode=tarpit`.
3. Put `offender_path` in a service-account-writable directory that other accounts cannot read or replace. On Windows, `C:/ProgramData/HighWall/data/offenders.json` is an example; do not use a public static directory or the audit-log directory.
4. Set the Webhook environment variable and enable `alerting.enabled=true` in the same service environment. Monitor `alert_sent_total`, `alert_failed_total`, and `alert_dropped_total`.

`monitor` does not slow or block requests, but a `confirmed` actor is still written to `offenders.json` so the correlation survives a restart. If you do not want persistent marks yet, do not enable `threat_detection` or point `offender_path` at a separate temporary directory.

Merge these key fields into the existing configuration (this fragment is not a complete configuration):

```json
{
  "threat_detection": {
    "enabled": true,
    "mode": "monitor",
    "confirm_after_seconds": 300,
    "containment_seconds": 300,
    "confirmed_containment_seconds": 900,
    "tarpit_hold_seconds": 15,
    "per_actor_tarpit_slots": 4,
    "global_tarpit_slots": 16,
    "offender_path": "/var/lib/highwall/offenders.json"
  },
  "ddos_detection": {
    "enabled": true,
    "escalation_seconds": 300
  },
  "alerting": {
    "enabled": true
  }
}
```

```powershell
$env:HIGHWALL_ALERT_WEBHOOK = "https://alerts.example.com/highwall"
$env:HIGHWALL_ALERT_TOKEN = "<16+ random characters>"
```

`HIGHWALL_ALERT_TOKEN` is an optional Bearer token, but production deployments should use one. Never write the token into the configuration file, README, command line, or audit logs. Webhooks require HTTPS by default and reject redirects and credentials embedded in the URL.

## Custom honeypots

A honeypot is an explicitly configured **exact-path decoy**. A request is matched against a normalized path only after it passes the client ACL and Host allowlist. On a hit, HighWall serves static content directly and never connects to the upstream. To avoid scanners receiving an early 403 from ordinary WAF or method rules, honeypot paths do not inherit the normal `allowed_methods`, Content-Type, Origin, read-only, or WAF constraints.

```json
{
  "enabled": true,
  "ban_seconds": 0,
  "presets": ["common"]
}
```

Security constraints:

- Matching is exact after path normalization. Prefix and wildcard matching are not supported, and the query string does not participate.
- `presets` can enable built-in groups directly: `common`, `secrets`, `wordpress`, `spring`, `admin`, `devops`, and `cloud`. Individual template names are also accepted. Explicit `routes` override presets by path.
- Response bodies must be embedded in the configuration and must not exceed 64 KiB. Only safe custom response headers are allowed; managed headers such as `Content-Type`, `Content-Length`, `Set-Cookie`, and `Server` are restricted.
- The URL, headers, and request body are never reflected. Request bodies, headers, cookies, Authorization, and query strings are not logged. Audit events contain only the method, path, source, status, and rule ID.
- When `ban_seconds` is greater than 0, the first hit bans the source immediately. Ban state is stored only in memory. Shared NAT egress may cause collateral bans; set it to `0` to disable.
- `delay_ms` is capped at 5000 for low-cost stalling, not as an anti-DDoS queue, and it still occupies a global in-flight slot.
- Never point a honeypot path at a real business endpoint, and never place real credentials, private keys, or lateral-movement information in a decoy.

For details, see [`docs/HONEYPOT.md`](docs/HONEYPOT.md). The template catalog and references are in [`docs/HONEYPOT-TEMPLATES.md`](docs/HONEYPOT-TEMPLATES.md). Hits appear as `honeypot_hit` audit events and update the `honeypot_hits_total`, `honeypot_bans_total`, `honeypot_ban_rejections_total`, and `honeypot_ban_entries` metrics.

## What it does not solve

HighWall is an L7 gateway, not an “absolute” defense:

- It **does not perform** traffic scrubbing or large-scale DDoS mitigation. Bandwidth, connection capacity, and upstream capacity still require network-layer protection.
- **Fingerprints are not identities.** HTTP/TLS shape can be spoofed or rotated, and `/24` or `/64` correlation can slow normal users behind a shared egress. Marks are risk correlation only, never authentication, attribution, or forensic proof.
- **DDoS alerts are not scrubbing.** `ddos_suspected` and `ddos_escalated` describe L7 signal anomalies; they do not identify the source or keep HighWall reachable when the link or host is saturated.
- It **cannot fix** authentication, authorization, IDOR, default credentials, key leakage, or unpatched vulnerabilities in the upstream application.
- It **cannot protect against** an attacker who already has root on the same host, shares the same namespace, can read process memory, or can sniff loopback traffic. It must be combined with separate users, namespaces, file ACLs, and network isolation.
- It **cannot prevent ransomware or destructive attacks**. An L7 gateway cannot stop a process with host write access from deleting files. Use low-privilege accounts, controlled folders, EDR, offline or immutable backups, and recovery drills.
- It **cannot replace a host firewall or network segmentation**. Client CIDR ACLs only process HTTP requests that reach HighWall; they do not cover DNS tunnels, RPC, raw sockets, or other non-HTTP traffic.
- `read_only` blocks only `POST`, `PUT`, `PATCH`, and `DELETE` by HTTP method. It cannot detect a bad business design that causes side effects through `GET`.
- Integrity pinning covers only exact static `GET` paths and status codes in the configuration. It does not cover query strings, dynamic pages, HEAD, WebSocket, or streaming responses.
- Honeypots cover only explicitly configured exact paths and cannot discover every scan. They may be fingerprinted, accidental bans can affect shared NAT sources, and they provide no high-interaction shell, file drop, or counterattack capability.
- The circuit breaker intentionally returns 503 while an upstream is failing repeatedly. It is failure isolation, not DDoS scrubbing or a capacity guarantee.
- It **does not proxy** WebSocket, HTTP/2, or bidirectional streaming responses; an Upgrade request is rejected. Responses are buffered up to `max_response_bytes`.
- WAF signatures are heuristic. They cannot guarantee coverage of every variant and may produce false positives. For an unknown application, start with `detect` before switching to `block`.
- Response DLP is also heuristic: it scans only the prefix limited by `response_scan_max_bytes` plus response headers, does not treat media type as an exemption, and makes heuristic attempts at UTF-8, Latin-1, and UTF-16. `Set-Cookie` is intentionally excluded to avoid false positives on login JWTs. Unknown encodings, fragmentation, binary formats, and custom business formats can still evade detection. Start unknown applications with `response_scan_mode=detect`.
- It does not add login, MFA, or authorization capabilities to the upstream. The upstream's own session security still matters.
- It does not manage certificates automatically. TLS certificates and private keys must be supplied and protected by the deployer.

## Architecture

```text
client / browser
      |
      | HTTP/1.1 (TLS optional)
      v
+---------------------- HighWall process ----------------------+
| strict parser -> connection/rate/ban + in-flight limits        |
| -> fingerprint -> threat score -> throttle/tarpit/mark         |
| -> client ACL -> Host/path -> honeypot OR route/read-only -> WAF/body |
| -> bounded upstream client <-> circuit breaker                 |
| -> response framing/sanitizer -> integrity pins -> DLP         |
| -> L7 DDoS signals -> async webhook alerts                     |
| -> audit + metrics                                             |
+---------------------------------------------------------------+
      |
      | HTTP/HTTPS, connection: close
      v
upstream application (ideally loopback or private network)
```

The admin plane is a separate loopback HTTP listener and cannot be reached from an external network.

## Quick start

Requirements: Windows PowerShell 5.1 or newer and Python 3.10 or newer. There are no third-party dependencies.

```powershell
Set-Location <HighWall checkout>
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 `
  -UpstreamUrl http://127.0.0.1:8080 `
  -AllowedHost app.internal `
  -WithDemoUpstream
```

The script will:

- generate `.runtime\config.json` with a loopback listener, admin plane disabled, WAF/DLP blocking, in-flight backpressure, an upstream circuit breaker, and the `common` honeypot preset;
- validate the configuration and start HighWall;
- with `-WithDemoUpstream`, also start a local demo upstream and verify Host rejection, normal forwarding, honeypot hits, and audit output;
- write the PID, logs, configuration SHA-256, and audit file. Repeated runs do not start duplicate instances. If the configuration changes after startup, `-Status` reports an error and asks for a restart.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -Status
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\quickstart.ps1 -Stop
```

Omit `-WithDemoUpstream` for a real upstream. Existing configuration is reused directly. If command-line arguments conflict with the configuration, the script returns an error instead of pretending the change succeeded. To modify an existing configuration, stop the instance and explicitly use `-Reconfigure`. The script merges only fields passed explicitly on the command line; unspecified routes, TLS, rate limits, scan modes, and other fields keep their current values. The old configuration is backed up as `config.json.bak.<timestamp>`.

You can also generate a configuration and inspect the effective values directly:

```powershell
python -m highwall init --upstream http://127.0.0.1:8080 --allowed-host app.internal --output config.json
python -m highwall check -c config.json
python -m highwall inspect -c config.json
```

`init` refuses to overwrite an existing file by default. For a partial update, use `init --base config.json --output config.json --force --listen-port 18091`; fields not specified explicitly are preserved. `inspect` expands honeypot presets and prints the effective listener, TLS, timeout, upstream circuit-breaker, ACL, WAF, response-scan, security-header, rate-limit, audit, and admin settings.

`config.example.json` remains the complete field reference. The quick-deployment script is intended only for local experiments and acceptance checks. It does not create Windows services, scheduled tasks, or ACLs. Use the deployment baseline for production hosting.

To enable the admin plane, change:

```json
{
  "admin": { "enabled": true }
}
```

Then generate a token and inject it through the environment:

```powershell
$env:HIGHWALL_ADMIN_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
python -m highwall serve -c .runtime\config.json
```

Access it with:

```powershell
curl.exe http://127.0.0.1:18091/healthz
curl.exe -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" http://127.0.0.1:18091/metrics
curl.exe -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" http://127.0.0.1:18091/offenders
curl.exe -H "Authorization: Bearer $env:HIGHWALL_ADMIN_TOKEN" "http://127.0.0.1:18091/audit/tail?lines=50"
```

The admin token is read only from the environment. Do not put it in `config.json`, a command line, or audit logs. Its length must be between 32 and 512 visible, non-space ASCII characters.

## Container image

Version tags build multi-architecture images and publish them to the GitHub Container Registry (GHCR). See the [HighWall GHCR package](https://github.com/Fallen-leaves089/highwall/pkgs/container/highwall) and the [v0.8.1 release](https://github.com/Fallen-leaves089/highwall/releases/tag/v0.8.1).

```bash
docker pull ghcr.io/fallen-leaves089/highwall:0.8.1
```

The image runs as non-root UID `10001` and starts `python -m highwall serve -c /etc/highwall/config.json` by default. No configuration is baked into the image. Without a mounted configuration, startup fails closed instead of falling back to an open policy.

Generate a container-oriented configuration first. Inside the container, the listener must bind `0.0.0.0`, and the audit file should be written to a persistent volume:

```bash
python -m highwall init \
  --upstream http://host.docker.internal:8080 \
  --listen-host 0.0.0.0 \
  --allowed-host app.internal \
  --audit-path /var/lib/highwall/audit.jsonl \
  --output config.json
```

`host.docker.internal` works with Docker Desktop. On Linux Docker, use a reachable service name or private address instead.

```bash
docker run --rm --name highwall \
  -p 18090:18090 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -v "${PWD}/config.json:/etc/highwall/config.json:ro" \
  -v highwall-data:/var/lib/highwall \
  ghcr.io/fallen-leaves089/highwall:0.8.1
```

- For TLS in production, mount the certificate and private key read-only and reference their in-container paths from the configuration.
- Do not expose the admin plane. It is disabled by default; if enabled, keep it on a controlled network.
- `latest` follows the most recent release tag. Pin an exact version for production deployments.

## Configuration highlights

- `policy.allowed_hosts`: exact authority allowlist. `example.com`, `example.com:443`, and `www.example.com` are three different values. Host casing is normalized and a trailing dot is removed.
- `policy.allowed_path_prefixes`: matches complete path segments. In production, narrow this to the actual business prefixes rather than leaving `/` indefinitely.
- `policy.deny_path_prefixes`: normalizes the path first, then rejects by prefix. The defaults cover `.git`, `.env`, `server-status`, and selected actuator endpoints.
- `policy.allow_path_parameters` / `allow_trailing_dot_or_space`: both default to `false`. Enable them explicitly only when legacy applications genuinely depend on `;jsessionid` or trailing dots/spaces. Compatibility mode affects route decisions only; the WAF still scans the complete path.
- `policy.waf_mode`: `detect` only records a hit; `block` rejects the request. Start an unknown application with `detect`.
- `policy.trusted_proxies`: populate this only when HighWall really sits behind a trusted reverse proxy. Never use `0.0.0.0/0`.
- `policy.allowed_client_networks` / `denied_client_networks`: optional CIDR ACLs with deny precedence. An empty list means no source-network filtering. This is an L7 decision and does not replace a host firewall.
- `policy.allowed_origins`: optional canonical Origin allowlist, for example `https://app.example.com`. Once configured, `POST`, `PUT`, `PATCH`, and `DELETE` must carry an allowed Origin, and cross-site writes are rejected. When empty, the original non-browser-compatible behavior is preserved.
- `policy.read_only`: global read-only switch; `routes[].read_only` applies only to the matching longest prefix. It cannot detect GET side effects.
- `policy.routes`: selected by longest path prefix. Supports `methods`, `read_only`, `max_body_bytes`, `max_concurrent`, `rate`, `rate_burst`, and `allowed_client_networks`. Route methods must be a subset of global `allowed_methods`; an empty route source list is rejected rather than silently allowed. `rate` is tokens per client per second; when `rate_burst` is omitted it defaults to the rate rounded up.
- `policy.honeypot`: disabled by default. Once enabled, exact normalized paths serve decoys, using built-in `presets` or custom `routes` with a static status, Content-Type, body, restricted response headers, server identity, first-hit ban, and a 0-5000 ms delay. Hits never touch the upstream and bypass ordinary method/Content-Type/WAF/read-only restrictions to preserve the trap. Host and client ACL checks still take precedence.
- `policy.response_integrity_mode` / `integrity_pins`: validate the status and response-body SHA-256 for normalized `GET` routes, case-insensitively. Supports `off`, `detect`, and `block`. Pin values must be updated through a controlled release process.
- `upstream.circuit_breaker`: `failure_threshold`, `window`, `open_seconds`, and `half_open_max_requests` control upstream failure isolation. Only timeouts, connection/protocol failures, and 5xx responses count as failures; 4xx means the upstream was reachable.
- `server.max_inflight_requests`: global in-flight request limit; `0` disables it. It should be lower than `max_connections` to create independent backpressure.
- `policy.allowed_body_content_types`: a request body with no Content-Type, or with a media type outside the list, is rejected.
- `policy.response_scan_mode` / `response_scan_max_bytes` / `response_scan_headers`: secret and debug-information scanning for upstream responses. Supports `off`, `detect`, and `block`; only a bounded prefix, 1 MiB by default, is scanned. Media types are not treated as an exemption, and decoding attempts cover UTF-8, Latin-1, and UTF-16. Response headers are scanned by default, with `Set-Cookie` always excluded.
- `server.max_connections_per_ip`: concurrent connection limit for a single source IP; `0` disables it, and trusted-proxy sources are not counted. It does not replace the total connection limit.
- `policy.routes[].max_concurrent`: route-level in-flight limit; `0` disables it, and it cannot exceed `server.max_connections`. Rejections return 503 with `Retry-After`.
- `rate_limit.auto_ban_threshold` / `auto_ban_window` / `auto_ban_seconds`: temporarily reject a source after protocol or policy errors accumulate within a time window; `threshold=0` disables it. Ban state is in memory only and is cleared on restart.
- `threat_detection`: multi-signal fingerprints, two-stage confirmation, bounded slow slots, and persistent marks. Disabled by default; start with `mode=monitor`, then move to `tarpit`. `containment_seconds=300` is the suspected window, while `confirmed_containment_seconds=900` is the confirmed slow window. `offender_path` must be a protected writable path.
- `ddos_detection`: aggregates L7 request rate, rejection ratio, connection saturation, TLS failures, and upstream errors. `escalation_seconds=300` means a 5-minute sustained signal window before escalation; `recovery_seconds` controls recovery events. It does not scrub bandwidth-based DDoS.
- `alerting`: asynchronous webhook delivery. When `enabled=true`, `HIGHWALL_ALERT_WEBHOOK` is required and defaults to HTTPS only; `HIGHWALL_ALERT_TOKEN` is optional. `include_client_ip` and `allow_http` both default to `false`. A full queue drops alerts and increments `alert_dropped_total` without blocking requests.
- `upstream.total_timeout`: absolute limit for the complete upstream exchange (connect, response headers, and response body); `read_timeout` is the per-read limit.
- `server.tls`: server-side TLS only; it does not replace upstream TLS verification. Certificate and key paths are resolved relative to the configuration file. The handshake runs in a worker thread under `handshake_timeout`, so a slow handshake does not block new accepts. When TLS is enabled without explicit HSTS, a one-year HSTS header is added automatically.
- `audit.path`: relative paths resolve from the configuration directory. The log directory must be protected from both the service account and the operations account. `audit.path_mode` supports `redact` (default), `hash`, and `exact`; the default mode cleans and decodes paths and redacts sensitive keys, following values, and obvious high-entropy segments.
- `admin.enabled`: disabled by default; when enabled, loopback binding and a token are mandatory.

See [`config.example.json`](config.example.json) for the complete example. Honeypot configuration is documented in [`docs/HONEYPOT.md`](docs/HONEYPOT.md), threat boundaries in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), the deployment baseline in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), and vulnerability reporting in [`SECURITY.md`](SECURITY.md). These detailed documents are currently written in Chinese.

## Troubleshooting

**No Webhook alert arrived.** Confirm that `alerting.enabled=true` is in the configuration and that `HIGHWALL_ALERT_WEBHOOK` exists in the same process environment as HighWall. A shell variable with alerting disabled sends nothing. Check that the receiver returns 2xx, then inspect `alert_failed_total` and `alert_dropped_total`. Keep the admin plane off the public internet.

**No attacker mark was created.** Only a `confirmed` actor is written to `offenders.json`; `suspected` traffic only receives a throttle or alert. Check `score_threshold`, `confirm_score`, and `confirm_after_seconds`, and verify that the service account can write `offender_path`. A mark is risk correlation, not authentication or a permanent ban.

**Normal users are being throttled.** Fingerprints are correlated by `/24` or `/64` source prefix, so shared NAT, proxy pools, and monitoring probes can be affected. Start in `monitor` mode, then tune thresholds and slots; use route ACLs or source exceptions to separate normal traffic when necessary.

**Why does HighWall not mitigate DDoS automatically?** It performs L7 signal detection and alerting only. Bandwidth-based L3/L4 DDoS, SYN floods, and scrubbing belong at the CDN, carrier, or scrubbing provider. HighWall may become unreachable before it can alert, so an external heartbeat is mandatory.

## Deployment principles

1. Bind to loopback for acceptance testing first, then bind the business interface. Do not expose it directly to the public internet.
2. Run under a dedicated low-privilege account and separate ACLs for configuration, audit, certificate directories, and the runtime account.
3. Do not start a production instance from a WSL-writable directory, a Codex workspace, or any directory writable by an attacker.
4. Keep the upstream on loopback or a private network and use a host firewall to restrict gateway-to-upstream and operations-to-admin traffic.
5. Enable TLS in production and grant private-key access only to the service account. Do not expose a self-signed certificate to external users.
6. Preserve existing network isolation and user/namespace separation. HighWall cannot replace operating-system boundaries.
7. Run `highwall check` and `highwall inspect` before starting the service. A bad configuration should make the process refuse to start rather than fail open.
8. Continuously ship audit logs off-host or write them to immutable storage. A locally writable log cannot resist an attacker with the same privileges. Run offline recovery drills regularly.
9. Prefer route-level read-only mode, method subsets, and source restrictions for high-risk write APIs. Do not let `GET` perform deletion, transfers, configuration changes, or other side effects.
10. Observe fingerprints and marks in `monitor` mode first, confirm shared NAT and normal automation are not harmed, then enable `tarpit`; protect the mark file and audit logs with the same ACL discipline.
11. Route DDoS alerts to an external NOC and configure an active heartbeat independent of the HighWall host. L3/L4 scrubbing, carrier coordination, and upstream capacity expansion remain outside this product.

## Tests and smoke checks

```powershell
Set-Location <HighWall checkout>
python -m unittest discover -s tests -v
```

Tests use temporary directories and temporary loopback ports only. They do not modify firewalls, port proxies, or external services.

To check only threat detection, attacker marks, slow slots, the DDoS state machine, and the Webhook queue:

```powershell
python -m unittest tests.test_threat -v
```

Before a release, also verify syntax and the example configuration:

```powershell
python -m compileall -q highwall
python -m highwall check -c config.example.json
```

The current suite covers strict parsing, path-parameter and trailing-dot bypasses, case-variant route bypasses, request encoding, a WAF bypass matrix, DLP (binary, UTF-16, response headers, and `Set-Cookie` false positives), route rate limits, HSTS, audit redaction, route policies, read-only mode, response pinning, the circuit-breaker state machine, in-flight and route-concurrency backpressure, custom honeypots, first-hit bans, attacker fingerprints/marks/slow slots, the DDoS state machine, alert deduplication and queue backpressure, the admin plane, configuration generation and overwrite rules, and the host-audit script. Windows integration tests start a real loopback gateway and verify TLS fingerprint correlation, confirmed slow responses, zero upstream forwarding for tarpitted requests, audit persistence, drift detection, reconfiguration backups, and shutdown flow without modifying the firewall, port proxies, or external services.

## License

HighWall is released under the [Apache License 2.0](LICENSE). Copyright and attribution information is in [NOTICE](NOTICE). You may use, modify, distribute, and commercially deploy it within the terms of the license. The license includes an explicit patent grant and patent-retaliation terms, and the software is provided without warranty.

HighWall is not a “set it and forget it” magic wall. It provides a set of auditable, testable, default-deny L7 invariants. Real security still depends on defense in depth.
