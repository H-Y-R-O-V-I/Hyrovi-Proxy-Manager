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
- unified correlated incident timelines that merge proxy requests, app/auth events, response actions and active challenge starts, with host/app/account/session/device entity summaries and explicit request-ID/source-IP match provenance;
- bounded response-action history for rate-limit/block start, removal and expiry;
- bounded daily security-event archive with configurable retention/minimum risk, independent of the rolling live nginx log window;
- critical/suspicious request inspection with per-request drill-down, explainable risk, similar-request correlation, linked attack sessions and response state/history in the admin UI;
- manual timed IPv4/IPv6 address or CIDR soft rate limits and hard blocks;
- continuous 5-second threat monitoring;
- persistent Observe/Enforce auto-response policy with configurable soft-rate-limit and hard-block thresholds/durations;
- conservative automatic response for public sources: suspicious attack signals are soft-limited first, repeated separated attack strikes escalate through an adaptive browser/API proof-of-work challenge before hard blocking, and single-event high-confidence attacks also receive that challenge first on Proxy Hosts;
- persistent soft-limit escalation state with configurable strike threshold, escalation window and strike cooldown;
- adaptive SHA-256 proof-of-work challenges with a 30-second hard-block grace period, bounded verification attempts, expiry, per-host duration/difficulty tuning, machine-readable browser/API challenge metadata, emergency bypass support and authenticated admin visibility/removal;
- protection against automatically blocking RFC1918/link-local/loopback source addresses;
- trusted exact IP/CIDR sources that remain observable but are excluded from automatic rate limits and blocking;
- per-proxy-host security modes (`Off`, `Observe`, `Protect`, `Strict`) stored outside the NPM schema, with host-specific soft/hard thresholds, response durations, challenge duration and proof-of-work difficulty;
- endpoint-specific path-prefix rules per Proxy Host, using longest-prefix matching to override the host mode for sensitive routes;
- transactional rollback if Nginx validation/reload or durable response-state persistence fails;
- automatic expiry of timed rate limits and blocks;
- authenticated app/auth security-event ingest and admin visibility;
- Ed25519 trusted-device identities for app/auth events, with per-device app scopes, monotonic replay counters, revocation and reset epochs;
- bounded operational security alerts with acknowledgement, deduplication and a separate read-only HYROVI One pull feed;
- safe custom detection rules with literal host/path/method/status/User-Agent matchers, explainable risk scoring, optional soft-response eligibility, retained-event hit analytics and read-only draft simulation;
- read-only system health/diagnostics with disk pressure, log/archive size and component-state visibility plus low-disk alerting;
- a dedicated HYROVI Sec navigation page.

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

App security-event ingest is disabled unless `HYROVI_SEC_INGEST_TOKEN` is configured with at least 32 characters. Only explicitly allowlisted security metadata is persisted; arbitrary extra JSON fields are discarded. See [HYROVI_SEC_APP_EVENTS.md](HYROVI_SEC_APP_EVENTS.md). Upstream HYROVI apps also receive `X-Hyrovi-Request-ID`, enabling exact proxy↔app event correlation without storing additional request content. Alerting and the read-only HYROVI One feed are documented in [HYROVI_SEC_ALERTS.md](HYROVI_SEC_ALERTS.md). Custom request rules are documented in [HYROVI_SEC_RULES.md](HYROVI_SEC_RULES.md). Health and diagnostic metadata are documented in [HYROVI_SEC_HEALTH.md](HYROVI_SEC_HEALTH.md).

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

## Non-browser challenge protocol

Browsers receive the existing HTML solver when they advertise `Accept: text/html`. API and other non-browser clients receive HTTP 429 with a JSON `challenge` object and `X-Hyrovi-Sec-Challenge-*` response headers.

The public challenge contract is versioned and contains no source IP, internal reason or response source metadata. Version 1 uses:

- algorithm: `sha256-leading-zero-bits`;
- input: `<challenge-id>:<nonce>:<counter>`;
- counter range: 0 through `maxCounter`;
- challenge discovery: `GET /.well-known/hyrovi-sec/challenge`;
- proof submission: `POST /.well-known/hyrovi-sec/challenge/verify` with JSON `{"id":"...","counter":123}`.

A non-browser client should:

1. preserve the original request locally when a response has `X-Hyrovi-Sec-Challenge: required`;
2. use the challenge from the 429 body or fetch the current challenge endpoint;
3. find a decimal counter whose SHA-256 digest has at least the requested number of leading zero bits;
4. submit the challenge ID and counter to the verify endpoint;
5. retry the original request only after verification returns `X-Hyrovi-Sec-Challenge: solved`.

Invalid counter formats are rejected before consuming a verification attempt. Successful verification removes the active challenge, so the same proof cannot be replayed against later requests.

## Response-state storage

HYROVI Sec owns:

- `/data/nginx/hyrovi-security/blocks.json`
- `/data/nginx/hyrovi-security/blocked-ips.conf`
- `/data/nginx/hyrovi-security/rate-limits.json`
- `/data/nginx/hyrovi-security/rate-limited-ips.geo`
- `/data/nginx/hyrovi-security/policy.json`
- `/data/nginx/hyrovi-security/escalations.json` (persistent soft-limit escalation counters)
- `/data/nginx/hyrovi-security/challenges.json` (active adaptive challenge state)
- `/data/nginx/hyrovi-security/trusted-devices.json` (trusted Ed25519 public keys and app scopes)
- `/data/nginx/hyrovi-security/trusted-device-state.json` (replay counters and last-seen state)
- `/data/nginx/hyrovi-security/alerts.json` (bounded operational alert state)
- `/data/nginx/hyrovi-security/detection-rules.json` (bounded custom detection rules)
- `/data/logs/hyrovi-sec-actions.log` (bounded JSONL response audit history)
- `/data/nginx/hyrovi-security/events/YYYY-MM-DD.jsonl` (bounded retained security-event archive)

Event archive defaults are intentionally storage-conscious: 14 days, minimum risk 20, with each daily file compacted when it reaches roughly 8 MiB. Normal/live requests still remain visible from the rolling nginx security log; the retained archive is for security-relevant history. Retention can be configured from 1 to 90 days and archive minimum risk from 0 to 100.

Response config changes are serialized and written atomically. Nginx is validated/reloaded before a new rate-limit or block state is considered successful. If durable state persistence fails, the previous Nginx response config is restored. On backend startup, the JSON state is reconciled back into the generated Nginx files so interrupted updates cannot leave stale enforcement behind. Existing HTTP hosts are regenerated through the `instrumentation-v5` upgrade marker so upgraded installations receive the current rate-limit, adaptive-challenge and machine-client challenge endpoints without manually re-saving hosts.

Automatic response defaults remain conservative: global soft restriction starts at risk 50 for 10 minutes, while the high-confidence threshold is risk 95. `Strict` host mode defaults to a lower soft threshold (45) and high-confidence threshold (90). Per-host challenge tuning accepts 1–120 minutes and 10–22 leading-zero proof bits. Untuned `Protect` hosts keep the previous 14-bit behavior and derive challenge duration from the soft-restriction duration, clamped to 5–30 minutes; `Strict` enforces at least 16 bits. During an active automatic soft restriction, three additional recognized attack strikes inside a 15-minute window escalate to an adaptive challenge, with a 60-second cooldown between counted strikes so one short burst cannot instantly consume the strike budget. A high-confidence attack on a Proxy Host also enters the challenge stage first. The challenged source receives at least a 30-second grace period to solve the proof; a later qualifying attack can then hard-block it for the configured block duration. If challenge creation fails, HYROVI Sec falls back to the hard-block path. Thresholds alone are not enough: events must contain recognized attack/reconnaissance signals, and private/loopback or trusted sources are excluded.

## Emergency recovery

Set `HYROVI_SEC_EMERGENCY_BYPASS=true` on the container and restart it if HYROVI Sec enforcement ever blocks legitimate administrative access. The s6 prepare phase clears only the generated deny/rate-limit/challenge files before Nginx starts, while `blocks.json`, `rate-limits.json` and `challenges.json` remain intact. The backend continues observing/archiving traffic but does not create automatic enforcement actions while the bypass is active.

The admin UI shows a prominent `BYPASS` warning when this mode is active. To restore enforcement, remove the environment variable (or set it to false) and restart the container; unexpired persisted response state is then regenerated into Nginx.

## Next security phases

1. package the authentication-event and signed-device protocol into reusable client SDKs;
2. connect HYROVI One to the read-only alert feed once its current worktree is clear, then add user-facing notification delivery;
3. add ASN-aware controls on top of the completed IPv4/IPv6 CIDR controls;
4. add staged rollout controls and richer rule-hit trend analytics on top of the completed retained-event simulation;
5. package the completed non-browser challenge protocol into reusable client helpers/SDKs and consider endpoint-specific challenge overrides.

## Upstream attribution

This project is based on Nginx Proxy Manager and retains its MIT license and upstream history. HYROVI-specific code is developed in this fork while keeping the upstream remote available for controlled synchronization.
