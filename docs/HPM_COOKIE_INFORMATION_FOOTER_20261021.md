# HYROVI HPM: information-only cookie footer — deployed 2026-10-21

Supersedes the choice-button UI described in HPM_COOKIE_FOOTER_20261021.md.

## Current behavior
- Standard eligible HPM proxy hosts display a small static footer at the bottom of the HTML document.
- No Erlauben/Ablehnen/Cookie-Einstellungen prompt or overlay.
- Existing necessary application cookies are not modified.
- Previously implemented server-side aggregate site activity remains automatic.
- The cross-subdomain 90-day visitor ID and individual clicks, scrolls, and page timelines still require a separately initiated opt-in.
- Previously consented browsers remain consented until revocation or expiry; they get a small "Besucherstatistik widerrufen" footer link.
- Revocation clears visitor cookie and tab session ID. GPC/DNT still disable the tracker.
- The programmatic window.hyroviAnalytics.grantConsent() remains available for an explicit opt-in elsewhere; page viewing never calls it.
- The settings() method no longer silently resets the consent preference.

## Deployment
Code: backend/internal/visitor_consent_script.js
Test: tests/shared-cookie-consent.test.mjs
VPS mount: /opt/hyrovi-hpm-vps/runtime/browser-cookie-v3/visitor_consent_script_v6.js
Pi mount: /opt/hyrovi-hpm/runtime/backend-users-20261020/internal/visitor_consent_script_v6.js
VPS backup: /opt/hyrovi-hpm-vps/runtime/backups/docker-compose.before-cookie-info-v6-20261021.yml
Pi backup: /opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-cookie-info-v6-20261021.yml

Both Compose files validated. Script SHA256 matched on VPS and Pi. HPM
containers restarted and were running with restarts=0. Public HPM, One, AI,
Stoneapp and tests endpoints all responded HTTP 200 after brief startup 502s.
Public scripts at /.well-known/hyrovi-analytics.js for AI and Stoneapp served
the new message without addButton controls. Node simulation passed.
Real Safari visual inspection remains unverified. Cached older scripts may
linger briefly.

## Privacy and scope
Server aggregate statistics do not equate to identifiable visitor profiles.
This change does NOT add unconsented tracking across domains. It is not a
replacement for a full privacy notice or legal review.
HYROVI One, the HPM admin UI and standalone tests.hyrovi.com do not currently
inherit this particular injected footer.

Rollback: restore the saved pre-switch Compose files on each node and
recreate hpm. No visitor history, secret files, or database migration changed.
