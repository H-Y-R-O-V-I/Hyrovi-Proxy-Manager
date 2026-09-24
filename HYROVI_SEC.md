# HYROVI Proxy Manager / HYROVI Sec

This repository is the HYROVI-owned fork of Nginx Proxy Manager.

Upstream remains configured as:

- `upstream`: `NginxProxyManager/nginx-proxy-manager`
- `origin`: `H-Y-R-O-V-I/Hyrovi-Proxy-Manager`
- HYROVI product branch: `main`

The goal is to preserve normal Nginx Proxy Manager functionality while adding HYROVI Sec as an integrated security control plane in the same gateway.

## HYROVI Sec v0 foundation

The first implementation adds:

- structured security telemetry for HTTP proxy, redirect and dead-host traffic;
- bounded request analysis in the backend;
- risk scoring and explainable signals;
- event-relative 60-second burst analysis so historical risk explanations remain stable;
- attack-session aggregation by source IP with stable bounded-window IDs, host summaries, top request patterns and incident timelines;
- bounded response-action history for rate-limit/block start, removal and expiry;
- bounded daily security-event archive with configurable retention/minimum risk, independent of the rolling live nginx log window;
- critical/suspicious request inspection with per-request drill-down, explainable risk, similar-request correlation, linked attack sessions and response state/history in the admin UI;
- manual timed IPv4/IPv6 soft rate limits and hard blocks;
- continuous 5-second threat monitoring;
- persistent Observe/Enforce auto-response policy with configurable soft-rate-limit and hard-block thresholds/durations;
- conservative automatic response for public sources: suspicious attack signals can be soft-limited first, while hard blocks still require high-confidence signals;
- protection against automatically blocking RFC1918/link-local/loopback source addresses;
- trusted exact IP/CIDR sources that remain observable but are excluded from automatic rate limits and blocking;
- per-proxy-host security modes (`Off`, `Observe`, `Protect`, `Strict`) stored outside the NPM schema, with host-specific soft/hard thresholds and durations;
- transactional rollback if Nginx validation/reload or durable response-state persistence fails;
- automatic expiry of timed rate limits and blocks;
- authenticated app/auth security-event ingest and admin visibility;\n- a dedicated HYROVI Sec navigation page.

### Data minimization

The security log deliberately does **not** store:

- query strings;
- request bodies;
- cookies;
- Authorization headers;
- API keys or tokens;
- referrer URLs.

The current event record contains only the minimum useful request metadata: timestamp, request ID, host, method, path without query string, response status, source IP, user-agent, request size, response bytes, request duration and upstream status.

The response-action audit log stores only response lifecycle metadata (time, source IP, response type/action, source/reason, response ID and expiry). It does not add query strings, request bodies, cookies, Authorization headers, API keys/tokens or referrer URLs. The file is bounded and compacted instead of growing indefinitely.
\nApp security-event ingest is disabled unless `HYROVI_SEC_INGEST_TOKEN` is configured with at least 32 characters. Only explicitly allowlisted security metadata is persisted; arbitrary extra JSON fields are discarded. See [HYROVI_SEC_APP_EVENTS.md](HYROVI_SEC_APP_EVENTS.md).\n
## Enforcement path

```text
Client
  |
  v
Nginx / HYROVI Proxy Manager
  |---- HYROVI Sec deny include -> hard block before upstream
  |
  |---- HYROVI Sec rate-limit geo -> 5 r/s, burst 20, HTTP 429 when exceeded
  |
  |---- structured security event -> /data/logs/hyrovi-sec.log
  |
  v
Configured upstream service

Backend security engine
  |---- bounded log tail
  |---- explainable risk signals
  |---- attack session aggregation
  |---- timed soft-restriction + block-list management
  |
  v
Admin UI / HYROVI Sec
```

## Response-state storage

HYROVI Sec owns:

- `/data/nginx/hyrovi-security/blocks.json`
- `/data/nginx/hyrovi-security/blocked-ips.conf`
- `/data/nginx/hyrovi-security/rate-limits.json`
- `/data/nginx/hyrovi-security/rate-limited-ips.geo`
- `/data/nginx/hyrovi-security/policy.json`
- `/data/logs/hyrovi-sec-actions.log` (bounded JSONL response audit history)
- `/data/nginx/hyrovi-security/events/YYYY-MM-DD.jsonl` (bounded retained security-event archive)

Event archive defaults are intentionally storage-conscious: 14 days, minimum risk 20, with each daily file compacted when it reaches roughly 8 MiB. Normal/live requests still remain visible from the rolling nginx security log; the retained archive is for security-relevant history. Retention can be configured from 1 to 90 days and archive minimum risk from 0 to 100.

Response config changes are serialized and written atomically. Nginx is validated/reloaded before a new rate-limit or block state is considered successful. If durable state persistence fails, the previous Nginx response config is restored. On backend startup, the JSON state is reconciled back into the generated Nginx files so interrupted updates cannot leave stale enforcement behind. Existing HTTP hosts are regenerated through the `instrumentation-v2` upgrade marker so upgraded installations receive the rate-limit hook without manually re-saving hosts.

Automatic response defaults remain conservative: global soft restriction starts at risk 50 for 10 minutes, while hard blocking starts at risk 95 for 60 minutes. `Strict` host mode defaults to a lower soft threshold (45) and hard threshold (90). Thresholds alone are not enough: the event must also contain recognized attack/reconnaissance signals, and private/loopback or trusted sources are excluded.

## Emergency recovery

Set `HYROVI_SEC_EMERGENCY_BYPASS=true` on the container and restart it if HYROVI Sec enforcement ever blocks legitimate administrative access. The s6 prepare phase clears only the generated deny/rate-limit files before Nginx starts, while `blocks.json` and `rate-limits.json` remain intact. The backend continues observing/archiving traffic but does not create automatic enforcement actions while the bypass is active.

The admin UI shows a prominent `BYPASS` warning when this mode is active. To restore enforcement, remove the environment variable (or set it to false) and restart the container; unexpired persisted response state is then regenerated into Nginx.

## Next security phases

1. expose per-host policy directly inside the normal Proxy Host editor and add endpoint-specific rules;
2. richer automatic response rules with cool-downs, escalation chains and browser/API challenges;
3. expand the authentication-event API into reusable client SDKs and deeper proxy/session correlation;\n4. trusted device identities based on cryptographic device keys;
5. correlated attack timelines across hosts, sessions, accounts and devices;
6. alerting and HYROVI One integration;
7. IPv4/IPv6 subnet and ASN-aware controls;
8. custom detection/rule management with safe validation and explainable matches.

## Upstream attribution

This project is based on Nginx Proxy Manager and retains its MIT license and upstream history. HYROVI-specific code is developed in this fork while keeping the upstream remote available for controlled synchronization.
