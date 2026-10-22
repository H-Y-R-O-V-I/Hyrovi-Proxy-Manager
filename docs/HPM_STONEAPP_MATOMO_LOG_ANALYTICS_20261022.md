# HYROVI Smart = Matomo-like private Stoneapp log analytics (22 Oct 2026)

## Clarification from user
The user did NOT mean "track only my own device." They want Analytics
for **all Stoneapp visits** with reports **only in their restricted HPM**,
like Matomo, without modifying Stoneapp and without a site cookie
banner or individual HPM registration per visitor.

## Production implementation
- Main view: `https://hpm.hyrovi.com/security` → HYROVI Sec →
  HYROVI Smart → Hosts & Analytics → Stoneapp.
- Matomo-style **aggregate web analytics** from existing HPM proxy
  access logs: approximate HTML pageviews by hour, top safe first-level
  site sections, coarse browser family, device class, OS, language
  region (not location), HTTP requests, bot hints and recent safe
  request samples. Filter Hide bots / All / Only bots affects
  pageview trends, top pages, device/browser summary and event list.
- The incorrect "Diesen Browser registrieren" control is REMOVED.
- Stoneapp injected HPM JavaScript immediately returns without
  reading/setting cookies or collecting browser-initiated events.
  No consent prompt, footer, popup, visitor ID or fingerprinting
  for non-registered visitors. The injected script URL still appears
  in HTML, but its client JS is inert on Stoneapp.
- **Important limitations:** These are server-log-derived counts,
  not unique humans/devices; no verified visitor IDs, session
  timeline or full Matomo JavaScript event tracking. "Aktionen"
  means safe HTTP server request categories and existing legacy
  historical browser event rows, not every UI click. In Germany,
  even cookieless JavaScript tracking may require consent.
- Zero changes to Stoneapp source, upstream app services,
  authentication or database. All changed files and services
  belong to VPS/Pi HPM proxy, exporter or HPM UI.
- Geographic origin cannot be inferred from browser language;
  no GeoIP used. No raw source IP, cookie, user agent, request ID,
  raw query or fingerprint in VPS→Pi export.
- VPS export capped (recent log tail 24h, 24 hourly buckets,
  12 top sections, 35 safe request samples per site).
- Analytics APIs require the existing HPM permissions; no
  unauthenticated report access (HTTP 403).
- Other HPM websites continue their existing tracking/consent
  behavior. Stoneapp-only exemption is explicit.

## Files changed
- `ops/vps_browser_activity_sync.py` now adds safe `smartHours`
  and `smartRoutes` to its per-host export.
- `backend/internal/security_visitors.js` handles the Pi log
  aggregation and exported VPS trend/route lists.
- `frontend/src/api/backend/securityVisitors.ts` types.
- `frontend/src/pages/Security/SmartHostsStudio.tsx`: removes
  enrollment and displays filtered 24h hourly bars and top pages.
- `backend/internal/visitor_consent_script.js`: Stoneapp script
  early return so client-side JS does not collect there.
- `tests/shared-cookie-consent.test.mjs`: Stoneapp browser-side
  analytics completely inert with and without old tracking cookies.
  Other-site consent tests unchanged.

## Live locations and rollbacks
VPS HPM:
- `/opt/hyrovi-hpm-vps/runtime/docker-compose.yml`
- `browser-cookie-v3/visitor_consent_script_stoneapp_log_only_20261022.js`
  mounted as `/app/internal/visitor_consent_script.js`.
- Backup:
  `/opt/hyrovi-hpm-vps/runtime/docker-compose.before-stoneapp-log-only-20261022.yml`
- VPS exporter:
  `/usr/local/libexec/hyrovi-vps-hpm-activity-sync.py`
- Exporter backup:
  `/usr/local/libexec/hyrovi-vps-hpm-activity-sync.before-matomo-log-20261022.py`

Pi HPM:
- `/opt/hyrovi-hpm/runtime/docker-compose.yml`
- Frontend:
  `/opt/hyrovi-hpm/runtime/frontend-stoneapp-log-only-20261022`
- Pi collector:
  `/opt/hyrovi-hpm/runtime/backend-stoneapp-log-only-20261022/security_visitors.js`
- Pi injected script:
  `/opt/hyrovi-hpm/runtime/backend-stoneapp-log-only-20261022/visitor_consent_script.js`
- Compose backup:
  `/opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-stoneapp-log-only-20261022.yml`

Rollback HPM by restoring the respective compose backup and running
`docker compose config -q` and
`docker compose up -d --no-deps --force-recreate hpm`.
Restore VPS exporter from backup and start
`hyrovi-vps-hpm-activity-sync.service` if needed.

## Tests and live checks
- TypeScript/Vite production build PASS.
- Node 15/15 existing privacy, Smart Traffic and host management
  tests PASS.
- VPS-export dry run proved the new data shape and no raw PII
  fields; latest ~100 KB well below export 1.5MB cap.
- VPS exporter systemd timer active; Pi read hourly and route
  arrays from live exported snapshot.
- Pi container `security_visitors.list()` live:
  Stoneapp VPS 73 HTTP requests, 17 approximate pageview requests,
  7 hour buckets and 10 route buckets; Pi Stoneapp had 0 in its
  recent local log tail. Numbers change as logs roll.
- HPM, Stoneapp login and HYROVI One HTTP 200 after Pi & VPS
  container recreation. Public security JS chunk HTTP200.
- Unauthorized Smart-hosts API returns HTTP403.
- Live Stoneapp proxy JS response includes an early return.
- No real Safari authenticated UI screenshot or interactive
  browser acceptance run; static build, server-side data path
  and public assets verified.
