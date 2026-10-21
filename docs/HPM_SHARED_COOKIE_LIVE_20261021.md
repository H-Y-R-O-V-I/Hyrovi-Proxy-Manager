# HYROVI HPM opt-in shared visitor cookie: LIVE 2026-10-21

This document supersedes HPM_SHARED_COOKIE_IDENTITIES_STAGED_20261021.md.
The consent banner is publicly delivered from the analytics script of standard
HPM-proxied hosts such as stoneapp.hyrovi.com/login and ai.hyrovi.com.

## Behavior
After a visible Erlauben choice, a random hyrovi_visitor_id UUID cookie is
stored at Domain=.hyrovi.com, Path=/, Secure, SameSite=Lax, Max-Age=7776000
(90 days). Ablehnen writes only a preference, not a visitor identity.
Do Not Track and Global Privacy Control are honored.
No sessionStorage identifier or browser analytics event is created before
consent. Cookie and session ID can be revoked. Sensitive login/payment/
account URLs are reported only as /[restricted], never their original path.
The script records general navigation/interaction event categories only;
not passwords, form content, click labels, keystrokes or raw coordinates.
Safari/browser anti-tracking measures may shorten cookie life.

The same 64-hex HMAC-SHA256 deviceKey is derived for a consented browser on
Pi and VPS, from the shared server key and browser UUID. Raw browser cookie
and secret are not emitted in the operator UI; distinct website sessions
remain separate within the same browser profile.

## Secret and production paths
PRIVATE secret mode 0600 root:root, same bytes on both nodes:
VPS /opt/nginx-proxy-manager/data/nginx/hyrovi-security/shared-visitor-secret
Pi  /opt/hyrovi-hpm/data/nginx/hyrovi-security/shared-visitor-secret
Never disclose or commit key contents.

Active VPS Compose: /opt/hyrovi-hpm-vps/runtime/docker-compose.yml
Mounted VPS tracker: /opt/hyrovi-hpm-vps/runtime/browser-cookie-v3/security_analytics_tracker.js
Mounted VPS script: /opt/hyrovi-hpm-vps/runtime/browser-cookie-v3/visitor_consent_script_v4.js
VPS backups: /opt/hyrovi-hpm-vps/runtime/backups/docker-compose.before-browser-cookie-v3.yml
and docker-compose.before-browser-cookie-v4.yml.

Active Pi Compose: /opt/hyrovi-hpm/runtime/docker-compose.yml
Mounted Pi tracker: /opt/hyrovi-hpm/runtime/backend-users-20261020/internal/security_analytics_tracker_v3.js
Mounted Pi script: /opt/hyrovi-hpm/runtime/backend-users-20261020/internal/visitor_consent_script_v4.js
Pi backups: /opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-browser-cookie-v3.yml
and docker-compose.before-browser-cookie-v4.yml.

## Verified live
- Authorized SSH sudo on Pi used for protected file installation.
- Both secret files identical (checked without displaying contents).
- Both live HPM modules returned sharedIdentityReady=true.
- Public Stoneapp + HYROVI AI JS has choice dialog and Domain=.hyrovi.com,
  the old VPS host-only LocalStorage version is gone.
- Public Stoneapp login and AI HTML include external analytics script;
  no blocking Content-Security-Policy response header observed.
- Synthetic fixed UUID test produced exactly matching 64-hex HMAC
  deviceKey on both running HPM Docker nodes, not printed.
- Node consent tests pass for first visit, opt-in, second subdomain,
  new session, decline, GPC, sensitive URL redaction and revocation.
- Both nodes running with no Docker restarts; HPM API, Stoneapp login,
  AI, HYROVI One and tests.hyrovi.com HTTP 200.
- Could not visually inspect actual Safari browser because the VPS has no
  headless browser installed; HTTP+script+DOM simulation tests passed.

## Scope and limits
Standard proxied websites are covered. The HPM admin frontend itself,
HYROVI One and custom tests.hyrovi.com lab currently do NOT embed this
shared banner script. They remain intentionally distinct. If a browser has
an earlier saved consent choice the banner is not shown again; web browsers
can cache the old external analytics script for up to five minutes. For a
first-time experience, open a private tab or clear relevant site data.
A complete privacy notice and proper legal basis may still be needed.

## Rollback
Restore the before-browser-cookie-v3 Compose backup for each node then
recreate only HPM. This does not remove the secret files. Never put secrets
into source control or unprotected command/log output.
