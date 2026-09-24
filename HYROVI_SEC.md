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
- attack-session aggregation by source IP;
- critical/suspicious request inspection in the admin UI;
- manual timed IPv4/IPv6 blocks;
- continuous 5-second threat monitoring;
- persistent Observe/Enforce auto-response policy with configurable risk threshold and block duration;
- conservative automatic blocking only for high-confidence public source IPs;
- protection against automatically blocking RFC1918/link-local/loopback source addresses;
- trusted exact IP/CIDR sources that remain observable but are excluded from automatic blocking;
- block rollback if Nginx validation/reload fails;
- automatic expiry of timed blocks;
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

## Enforcement path

```text
Client
  |
  v
Nginx / HYROVI Proxy Manager
  |---- HYROVI Sec deny include -> block before upstream
  |
  |---- structured security event -> /data/logs/hyrovi-sec.log
  |
  v
Configured upstream service

Backend security engine
  |---- bounded log tail
  |---- explainable risk signals
  |---- attack session aggregation
  |---- block-list management
  |
  v
Admin UI / HYROVI Sec
```

## Block storage

HYROVI Sec owns:

- `/data/nginx/hyrovi-security/blocks.json`
- `/data/nginx/hyrovi-security/blocked-ips.conf`
- `/data/nginx/hyrovi-security/policy.json`

Block config changes are serialized and written atomically. Nginx is validated/reloaded before the new block state is considered successful. If durable state persistence fails, the previous Nginx block config is restored. On backend startup, `blocks.json` is reconciled back into the generated deny include so interrupted updates cannot leave stale enforcement behind.

## Next security phases

1. per-host security policy and protection mode;
2. richer automatic response rules with cool-downs and escalation chains;
3. authentication-event SDK so apps can report login/session/device events;
4. trusted device identities based on cryptographic device keys;
5. durable event store and retention controls instead of a bounded log window;
6. correlated attack timelines across hosts, sessions, accounts and devices;
7. rate limiting/challenges before hard blocking;
8. alerting and HYROVI One integration;
9. IPv4/IPv6 subnet and ASN-aware controls;
10. emergency bypass/recovery controls.

## Upstream attribution

This project is based on Nginx Proxy Manager and retains its MIT license and upstream history. HYROVI-specific code is developed in this fork while keeping the upstream remote available for controlled synchronization.
