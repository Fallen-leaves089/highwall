# Security Policy

## Supported versions

`0.1.x` is the current preview line. There is no long-term support commitment yet.

## Reporting

Do not open a public issue for a suspected vulnerability. Report it privately to the maintainer with:

- affected version and platform;
- a minimal reproduction or configuration;
- impact and whether the issue is reachable without local access;
- any suggested fix.

## Scope

L4Wall is a TCP gateway, not a host firewall or a complete DDoS mitigation product. The following are documented limitations rather than vulnerabilities unless they violate the invariants in `docs/THREAT_MODEL.md`:

- bandwidth-based DDoS and SYN floods that never reach the accept loop;
- spoofed source addresses;
- a compromised host that can read process memory or modify configuration/audit files;
- traffic that mimics legitimate connection behavior closely enough to evade heuristic scoring;
- a private Redis shared-ban source that is writable by an untrusted party and injects over-broad or malicious bans;
- upstream application vulnerabilities.

## Secrets

The admin token is read from the environment variable named by `admin.token_env`. The optional shared Redis password is read from `threat_detection.shared_bans.password_env` when that field is non-empty. Neither secret is written to the configuration file or audit log. Do not put tokens in command-line arguments or committed files.

## Audit data

Audit events include source IP addresses by default. Set `audit.include_client_ip=false` if that data must not be retained, and protect the audit directory with host permissions.

