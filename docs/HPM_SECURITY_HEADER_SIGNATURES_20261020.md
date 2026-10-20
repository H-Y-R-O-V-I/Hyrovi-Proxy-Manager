# HYROVI Sec — Automatic server-side header signature counts

Production deploy: 2026-10-20 approx 17:49 CEST.

## Goals and limits
HPM already computes HMAC fingerprint hashes from incoming request headers
as part of security detection in backend/internal/security_analytics_tracker.js.
This UI extension only COUNTs distinct security header combinations per
domain in a bounded log tail, without exposing or storing any signature ID.

Headers already received: user_agent, accept_language, sec_ch_ua,
sec_ch_ua_mobile, sec_ch_ua_platform.
The export never transports raw headers, fingerprint hashes, IP, cookies or
user/session identifiers from the VPS to the Pi. Signature counts are per
domain/node and cannot link users across sites. A single visitor may produce
multiple header combinations, and many visitors can share one combination.
The new automation indicator counts requests with explicit bot/tool markers
in the user-agent, not a verified malicious-bot classification.

## Implementation
- ops/vps_browser_activity_sync.py: transient in-memory per-domain
  12-byte SHA-256 header digest set; export only integer
  clientSignatures and automationSignals in the existing one-minute summary.
- backend/internal/security_visitors.js: compute equivalent counts
  for Pi on demand from bounded proxy-log tail; merge VPS integer counts.
- frontend/src/pages/Security/UsersStudio.tsx: UI shows the two new
  per-domain security metrics in Users > Uebersicht and a dedicated
  Fingerprint Studio aggregate view in Users > Liste.

No client-side data storage, no new tracking cookie, no tracking consent
widget and no persistent individual identity record were introduced by this
feature. This does NOT remove an operator's duty to provide a suitable
privacy notice or determine the legal basis for applicable personal-data
processing. It also does not enable cross-site person tracking.

## Deployment and verification
VPS installed at /usr/local/libexec/hyrovi-vps-hpm-activity-sync.py
and systemd timer hyrovi-vps-hpm-activity-sync.timer remains active.
Pi mounted backend:
 /opt/hyrovi-hpm/runtime/backend-users-20261020/internal/security_visitors_v7.js
Pi frontend:
 /opt/hyrovi-hpm/runtime/frontend-security-signatures-20261020
Previous compose backup:
 /opt/hyrovi-hpm/runtime/backups-users-20261020/compose-pre-signature-ui.yml
Pi HPM health HTTP 200 after service initialization; public hpm.hyrovi.com/api/
and one.hyrovi.com HTTP 200. Live VPS Stoneapp sample: 18 distinct technical
header combinations and 17 bot/tool-marker requests, not 18 people or
17 confirmed bad bots. At same time 38 individually unlinked anonymous
browser events in current synced export (33 Stoneapp).
