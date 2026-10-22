# HYROVI Datenschutzerklärung und Entfernung des schwebenden Cookie-Buttons (22.10.2026)

## User request
"Bei Datenschutz soll jetzt was stehen und Cookie Einstellungen soll weg."
The user wants a real public privacy page at
`https://hyrovi.com/datenschutz` and NO persistent "Cookie-Einstellungen"
floating button on HPM-injected pages. Existing first-visit neutral
banner with equally visible Accept/Reject must remain unchanged.

## Page and consent behavior
- A first-party static German privacy notice was created under
  `ops/hpm-privacy-20261022/datenschutz.html`; active on the apex
  via VPS HPM Nginx. Includes technical server/security logs,
  optional consent-gated Matomo-like browser analytics, 90-day
  shared domain cookies, coarse data categories, Cloudflare/network
  providers, legal bases, data-subject rights and storage overview.
- The privacy page contains a voluntary **"Tracking-Einwilligung
  widerrufen"** button, which sets the shared
  `hyrovi_analytics_consent=0` for up to 90 days and removes the
  `hyrovi_visitor_id` and prior Stoneapp-specific browser IDs.
  The privacy page itself has no HYROVI tracking client.
- It does NOT falsely claim full legal compliance: the actual
  responsible person's/organization's identity + full contact
  details and exact technical log-retention periods are not known.
  The document openly states these missing details and needs a
  legal/admin final review. DO NOT publish user identity without
  explicit consent. The public page is substantive but not complete
  for GDPR Article 13 as of deployment.
- `backend/internal/visitor_consent_script.js`:
  removes the floating persistent `showSettingsLink()` functionality
  entirely. After Accept or Reject, the consent banner goes away
  and nothing remains. The choice remains persisted for all
  `.hyrovi.com` hosts via the existing 90-day cookie.
  During the initial first-visit prompt only, an underlined
  **Datenschutzerklärung** link points to
  `https://hyrovi.com/datenschutz`.
  Both consent choices, GPC/DNT handling and server-side security
  logging behavior remain unchanged.
- The old `window.hyroviAnalytics.settings()` programming API was
  retained for compatibility but no visible user-facing settings
  button is shown; direct withdrawal is available through the
  public privacy page.

## VPS HPM nginx-only apex route
The apex `hyrovi.com` was previously NPM's default fallback
"Host not configured". Cloudflared routes public apex HTTPS to
VPS local HPM port 80. A new **exact path only** HPM nginx vhost
serves `/datenschutz` as a static file with strict CSP; `/`
and all other paths still use the previous fallback HTML. Other
proxy hosts are not changed.

Source:
- `ops/hpm-privacy-20261022/apex.conf`
- `ops/hpm-privacy-20261022/datenschutz.html`

Live:
- `/opt/nginx-proxy-manager/data/nginx/hyrovi-privacy/apex.conf`
- `/opt/nginx-proxy-manager/data/nginx/hyrovi-privacy/datenschutz.html`
- `/opt/nginx-proxy-manager/data/nginx/custom/http.conf` includes
  `/data/nginx/hyrovi-privacy/apex.conf`

Nginx backup:
`/opt/nginx-proxy-manager/data/nginx/custom/http.conf.before-hyrovi-privacy-20261022`

Revert apex path only by restoring the preceding `http.conf`
and `docker exec hyrovi-proxy-manager nginx -t` followed by
`docker exec hyrovi-proxy-manager nginx -s reload`.
The HTML/partial may remain harmless and unused in persistent storage.

## New HPM consent script mounts
VPS:
`/opt/hyrovi-hpm-vps/runtime/docker-compose.yml` mounts
`/opt/hyrovi-hpm-vps/runtime/browser-cookie-v3/visitor_consent_script_privacy_20261022.js`
to `/app/internal/visitor_consent_script.js`.
Backup:
`/opt/hyrovi-hpm-vps/runtime/docker-compose.before-privacy-banner-20261022.yml`.

Pi:
`/opt/hyrovi-hpm/runtime/docker-compose.yml` mounts
`/opt/hyrovi-hpm/runtime/backend-privacy-20261022/visitor_consent_script.js`
to `/app/internal/visitor_consent_script.js`.
Backup:
`/opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-privacy-banner-20261022.yml`.

Both HPM containers safely recreated and healthy. Reverting either
tracking change: restore respective Compose backup and run
`docker compose config -q && docker compose up -d --no-deps --force-recreate hpm`.

## Verification
- Public `https://hyrovi.com/datenschutz` HTTP 200,
  Content-Type `text/html; charset=utf-8`, Nginx CSP,
  contains correct title/content.
- Public `https://hyrovi.com/` remains HTTP 200 unchanged.
- Public HPM Stoneapp, AI (VPS) and Search (Pi) analytics
  scripts are byte-for-byte identical:
  SHA256 `1921c2013cbf8d8d331a178ee041f9a03962a5c2c2ff9c4991770db18b2cd0db`.
  None contains floating settings script/link; each links the
  first-visit prompt to the privacy page.
- Nginx `nginx -t` successful, services HPM, Stoneapp and
  HYROVI One HTTPS 200, anonymous HPM Smart API 403.
- Node tests **18/18 PASS**, including site privacy-page JS
  cookie withdrawal and the absence of cookie settings
  controls after consent/decline, plus existing Security tests.
- Python analytics test PASS.
- Authenticated iPad Safari visual UX was not tested.
- Tracking script may have been cached by browsers for up to
  300 seconds before the update; refreshing after cache expiry
  obtains the new behavior.
