# HYROVI Smart Analytics · 2026-10-21 deployment

## Status
Live. Adds a Matomo-like, first-party, consented analytics test mode at
`tests.hyrovi.com` with a separate HPM admin page under Security > Users >
HYROVI Smart · Analytics. Existing HPM Smart aggregate-security view remains
accessible from an adjacent button.

Only the test site collects new device diagnostics. Do not represent this as
already enabled on other HPM hosts or other HYROVI domains.

## Data model and scope
- User explicitly starts a test session on tests.hyrovi.com, after an
  information screen. No automatic tracking before that interaction.
- Server creates a random per-session token. SQLite stores a derived session
  identifier and test name; no analytics cookie, device ID, persistent
  cross-session identity, or new fingerprint calculation.
- Diagnostics are whitelisted, validated strings:
  browser family, platform, language, timezone, screen and viewport classes,
  screen and viewport pixel sizes, coarse CPU/memory, touch, pixel ratio,
  theme, motion preference, device class, orientation, color depth, effective
  connection type, and supported browser feature labels.
- Events are strict typed enums: page, section, button, scroll, heartbeat,
  visible. No form data, passwords, keypresses, click coordinates, or
  activity on other websites.
- 24-hour retention, max 1200 events per session and 120 events/minute;
  session starts limited to 100/hour. Bounded 750 KB snapshot transferred
  VPS -> Pi by preexisting systemd exporter approximately every 7 seconds.
- Old test sessions may retain historical header signatures until expiration.
  New sessions do not calculate or store one. The original test-lab signing
  key file is not deleted, to preserve historical operational state.

## Implementation
- `test-studio/app.js`: extended browser diagnostics collected after
  explicit Test starten.
- `test-studio/server.py`: validated diagnostics allowlist; no new header
  signature, existing SQLite schema remains compatible.
- `test-studio/index.html`: full notice of recorded data.
- `backend/internal/security_visitors.js`: expanded sanitized diagnostics
  mapping, no new stable device ID.
- `frontend/src/pages/Security/SmartAnalyticsStudio.tsx`: new HPM view
  showing session list, device details and action timeline, independently by
  session identifier rather than fingerprint grouping.
- `frontend/src/pages/Security/UsersStudio.tsx`: navigation to Analytics;
  existing HPM Smart Security module remains as secondary view.
- `frontend/src/pages/Security/TestsStudio.tsx`: explain that new sessions
  are no longer grouped by generated header signatures.
- `tests/test_smart_analytics.py`: test diagnostic input validation and
  rejection of private/unexpected fields.

## Runtime and backup
VPS collector: `/opt/hyrovi-test-studio`,
`hyrovi-test-studio.service`, SQLite at
`/var/lib/hyrovi-test-studio/events.sqlite3`;
VPS backup of original service code and UI:
`/opt/hyrovi-test-studio/backups/smart-analytics-20261021`.
Exporter:
`hyrovi-test-studio-export.timer` and `.service`.

Pi HPM compose:
`/opt/hyrovi-hpm/runtime/docker-compose.yml` with:
- frontend at `/opt/hyrovi-hpm/runtime/frontend-smart-analytics-20261021`
- visitors backend at `/opt/hyrovi-hpm/runtime/backend-smart-analytics-20261021/security_visitors.js`
- original `backend-smart-20261021/security_smart.js` retained.

Pi compose backup:
`/opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-smart-analytics-20261021.yml`.
The last frontend change was applied by atomic index replacement; previous
index remains at
`frontend-smart-analytics-20261021/index.before-last-analytics-fix.html`.

## Validation (live)
- Python unit test diagnostic allowlist PASS.
- Node existing security/consent tests: 6/6 PASS.
- TypeScript/Vite production build PASS.
- HPM, HYROVI One, test domain HTTP 200.
- Synthetic start 201/event 202: SQLite stored expected diagnostics + event.
- Direct Pi HPM read of exported synthetic test session confirmed new diagnostic
  fields and its timeline; synthetic row deleted immediately after verification.
- Separate test after disabling header signature confirmed new SQLite
  `signature` is empty. Test row deleted.
- Legacy logs and HPM old opt-in visitor profiles remain untouched.

## Restrictions
- No recording across every HPM host yet.
- No persistent physical-device identification, no cross-session merge.
- No real participant Safari visual QA was performed by the automation.
- Detailed device analytics on other sites should require an appropriate
  lawful basis and disclosed participation conditions.
