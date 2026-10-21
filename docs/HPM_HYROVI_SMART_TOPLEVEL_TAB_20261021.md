# HYROVI Sec · HYROVI Smart as independent top-level tab (2026-10-21)

## User request
Move Smart Analytics out of the old Security > Users nested flow and
make it an independent main tab inside HYROVI Sec.

## Implementation
Changed only the HPM frontend in the existing
`fix/sec-users-studio-20261020` branch.

- `frontend/src/pages/Security/index.tsx`: the root security tab selector
  now includes `smart`, rendering `SmartHub` independently from `UsersStudio`.
  Main order: Dashboard, Users, HYROVI Smart, Blocked IPs, Access & groups,
  Settings. Shortened the old Users tab label to simply `Users`.
- `frontend/src/pages/Security/SmartHub.tsx`: independent component with
  Analytics as the default; the existing aggregate Smart Security analysis
  remains accessible through an internal button. Security data query only
  runs when that internal subview is selected.
- `frontend/src/pages/Security/SmartAnalyticsStudio.tsx`: removed the
  misleading Back to All Hosts button and Users breadcrumb.
- `frontend/src/pages/Security/SmartStudio.tsx`: updated breadcrumb and
  return action back to Analytics.
- `frontend/src/pages/Security/UsersStudio.tsx` and
  `AllHostsStudio.tsx`: completely removed the Smart Analytics nested
  navigation and unused view branches; existing Users functions unchanged.
- `frontend/src/pages/Security/Security.module.css`: tab strip allows
  horizontal scrolling on mobile/iPad while each tab label stays intact.

## Production
Pi HPM frontend remains in existing read-only Docker directory
`/opt/hyrovi-hpm/runtime/frontend-smart-analytics-20261021`, served by
`hyrovi-proxy-manager`. New static assets extracted before atomically
replacing `index.html`. Prior index backed up to
`index.before-top-level-smart-tab-20261021.html`.
No backend service, proxy rules, data collector, analytics data or database
changed. No container restart required.

## Verification
- TypeScript + Vite production build: PASS
- Existing Node security and consent tests: 6/6 PASS
- Python analytic validation test: PASS
- Public HPM security page, HPM API, tests.hyrovi.com and HYROVI One
  return HTTP 200
- New security frontend chunk `Security-CNqhLW5N.js` served publicly HTTP 200
- Public index and live Pi mounted index match new `index-BQWgGKDi.js`
- Unauthenticated `/api/security/test-studio` remains HTTP 403
- HPM container remained up; no service restarts
- A real authenticated iPad Safari UI interaction was not available to
  validate visually.

## Rollback
On Pi:
```bash
cd /opt/hyrovi-hpm/runtime/frontend-smart-analytics-20261021
cp index.before-top-level-smart-tab-20261021.html index.html
```
The previous assets were not removed, so this restores the old navigation
without altering data. Refresh authenticated browser afterwards.
