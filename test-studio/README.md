# HYROVI Test Studio, 2026-10-20

Scope: tests.hyrovi.com only. This is an isolated pilot of a first-party test
session lab, not general website-wide person surveillance.

## Participant flow
A visitor opens https://tests.hyrovi.com, enters a freely chosen test name,
and presses Test starten. Only then do page, button, scroll, navigation and
visibility/heartbeat events get sent. The site does not send input contents,
keystrokes, passwords or actions on other websites. It sets no cookies.
The page explains the test analytics and diagnostics before the test starts.

The HPM Sec > Users tab opens Live Test Studio by default.
HPM administrators can see the most active test sessions and select a session
for precise timestamps, action types, name, session duration, and a scoped
header HMAC fingerprint with browser/platform/language. A test session is NOT
proof of a specific human identity, and identical header signatures may
belong to different devices. Signatures are not used to link domains.

Scoring: button actions 4 points each, section changes 2, page views 1,
scroll milestones 1; heartbeats affect online/active status, not rankings.
Users appear within about 7-12 seconds of starting and interacting.
The HPM web UI polls at 5s intervals.

## Public routing
Cloudflare explicit CNAME tests.hyrovi.com points at existing VPS
hyrovi-vps tunnel. Its wildcard ingress forwards requests to VPS HPM port 80.
VPS HPM serves the test-only vhost, config:
 /opt/nginx-proxy-manager/data/nginx/hyrovi-test-site/tests.conf
and an include appended to /data/nginx/custom/http.conf.
Original http.conf backup:
 /opt/nginx-proxy-manager/data/nginx/custom/http.conf.before-test-studio-20261020
The tracked nginx/tests.conf is the corresponding vhost template.
Existing proxy hosts were not modified, certificates remain untouched.
Host UFW allows only br-67734a8d584c / 172.18.0.0/16 to 172.18.0.1:7346.
The public DNS record was created explicitly for this test hostname.

## Services and storage
VPS site app files are installed under /opt/hyrovi-test-studio,
running under dedicated unprivileged hpm-test systemd user via
hyrovi-test-studio.service. HTTP bound to 172.18.0.1:7346, reachable via
HPM docker bridge only. Persistent SQLite DB:
 /var/lib/hyrovi-test-studio/events.sqlite3
Signature HMAC key stored privately in that data dir, mode 0600, never in Git.

VPS exporter test-studio/export.py is installed at
 /usr/local/libexec/hyrovi-test-studio-export.py
systemd unit/timer hyrovi-test-studio-export.* refresh every ~7 seconds
and push only a bounded JSON file over SSH to the Pi:
 /opt/hyrovi-hpm/runtime/vps-hpm-sync/tests-studio.json
The existing Pi read-only directory mount maps to /data/vps-hpm-sync.

Pi production HPM backend:
 /opt/hyrovi-hpm/runtime/backend-users-20261020/routes/security_tests.js
 /opt/hyrovi-hpm/runtime/backend-users-20261020/internal/security_visitors_v9.js
Pi production HPM frontend:
 /opt/hyrovi-hpm/runtime/frontend-teststudio-v2-20261020
The original Pi Compose before the test studio rollout is backed up:
 /opt/hyrovi-hpm/runtime/backups-users-20261020/compose-pre-tests-studio.yml
Pre-fingerprint-addition backup:
 /opt/hyrovi-hpm/runtime/backups-users-20261020/compose-pre-teststudio-fingerprint-v2.yml

## Security and bounded behavior
A random browser-tab test session token is sent only to the first-party
test API in its X-Test-Session header. Server stores its SHA-256 derived
identifier, not the token. After explicit start, a test-only HMAC of
already-sent HTTP header values is stored on that session, along with
coarse browser family, OS/platform, and Accept-Language. No canvas,
WebGL, hidden probes, persistent cross-site identifiers, or cookies.
No individualized profiles are generated on other HYROVI websites.

Accepted test actions are strict enums. Body max 1024 bytes; each test
session is limited to 1200 total events and 120/minute; test starts
limited to 100/hour. Sessions/events expire after 24h, with background
cleanup even if no new session starts. Export is limited to 750KB, up to
100 sessions and up to 250 latest event details per session (older
timeline may be truncated to protect the service but aggregate totals
stay accurate). Snapshot older than 30s is rejected by Pi HPM.
HPM GET /api/security/test-studio and /:id require logs:list and return
HTTP 403 for unauthenticated users.

## Verified tests
Public HTTPS site, JS and CSS HTTP 200; health route HTTP 200.
Cloudflare CNAME matches VPS HPM and its upstream answers correctly.
HPM API HTTP 200 and unauthenticated test route HTTP 403.
Python syntax, Node backend syntax, TypeScript/Vite production build pass.
Synthetic Safari iOS/iPadOS clients posted live events through public
Cloudflare/HPM, persisted to SQLite, transferred via the VPS service,
and were read from the actual Pi HPM backend testStudioList and
testStudioDetail methods. Complete six-event test reported nine score
points; initial partial scores converged at the subsequent sync tick.
Synthetic sessions were deleted after verification. Server and export
systemd units/timer are active; HPM and HYROVI One HTTP 200.

## Rollback
Restore the Pi Compose backup and recreate only HPM, leaving event
archives, HPM certificates and other proxy hosts unchanged.
To disable the standalone public test site, disable its systemd service
and exporter timer, remove the vhost include and config from VPS HPM
after nginx -t, then reload nginx. Remove the explicit Cloudflare
DNS record separately if restoring wildcard behavior is desired.
Never disclose the SQLite DB private signature key.
