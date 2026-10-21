# HPM shared browser cookie identity — STAGED, NOT LIVE (2026-10-21)

User requested a small text cookie connecting repeat browser sessions on all
*.hyrovi.com hosts. Existing Pi analytics already wrote
hyrovi_visitor_id to Domain=.hyrovi.com for expressly activated clients,
but the VPS's older backend version used a host-only __hyrovi_vid
localStorage/cookie implementation; Pi and VPS had different HMAC secrets.
Without a shared mapping the same browser became two visitor profiles,
and without a consent activation the visitor list remained empty.

## Local implementation
- Browser JS script creates a random UUID hyrovi_visitor_id cookie with
  Secure, SameSite=Lax, Path=/ and Domain=.hyrovi.com; Max-Age 90 days.
- Cookie is only created AFTER an explicit clear Erlauben choice.
  The compact first-party visitor analytics choice also has Ablehnen;
  decline stores only a preference and generates NO identity cookie.
  If DNT or Global Privacy Control is enabled, no prompt/collect/ID.
- Existing JS API allows grantConsent/revokeConsent/settings. Revoke
  deletes visitor ID and leaves a nontracking choice cookie value 0.
- No consented page, scroll, route, or generic click telemetry is sent
  before activation. Passwords and form values are never collected.
  Sensitive auth/checkout/login/account URL paths are replaced by
  /[restricted] in analytics; sensitive-site clicks are excluded.
- Session ID remains independent per browsing session; the shared visitor
  ID joins sessions for a browser using .hyrovi.com cookies.
- Each node backend derives a 64-character opaque, globally consistent
  deviceKey via HMAC-SHA256 shared secret with a version namespace.
  Raw cookie values are not exported into analytics profiles. Cross-node
  source machine identity is not inferred from IP or UA.
- If the shared key is absent, backend intentionally emits no deviceKey
  instead of creating inconsistent IDs. Each node retains its separate
  per-node secret for other security analytics.
- No extension to unrelated registrable domains and no guarantee browsers
  retain JS-set cookies a full 90 days under anti-tracking restrictions.

## Testing performed
Shared cookie Node tests PASS:
no storage/event before opt-in, shared ID across Stoneapp+AI hosts, separate
session IDs, decline, GPC, revoke, and sensitive login path redaction.
Node browser-script generation and backend syntax check PASS.

## Deployment status and blocker
NOT LIVE. VPS key file provisioned locally at
/opt/nginx-proxy-manager/data/nginx/hyrovi-security/shared-visitor-secret
(mode 0600; NEVER print/share or add to Git). Transfer to the Pi data
directory was blocked by permissions. A follow-up request to inspect the
non-interactive admin privilege was blocked by tool safety checks.
No workaround was attempted. No backend/Compose files were changed
or containers restarted. Before production launch, obtain authorized
Pi admin deployment access, install the exact same shared secret mode 0600
in /opt/hyrovi-hpm/data/nginx/hyrovi-security/shared-visitor-secret,
deploy script + analytics tracker on BOTH VPS and Pi using their respective
active Compose setups, then verify cross-node deviceKey equality,
tests, and HPM visitor list under real affirmative activation.
The active VPS Compose is /opt/hyrovi-hpm-vps/runtime/docker-compose.yml;
Pi Compose is /opt/hyrovi-hpm/runtime/docker-compose.yml.
Do not confuse VPS with old /opt/nginx-proxy-manager/docker-compose.yml.

## Legal / product boundary
Cross-site visitor recognition is not an automatically consent-exempt
security-log function. This implementation contains explicit opt-in,
privacy-protected routes and revocation; additional privacy notices and
retention/legal assessment for each public site may still be required.
