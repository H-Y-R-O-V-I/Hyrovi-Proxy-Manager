# HPM-only Stoneapp browser enrollment, no Stoneapp banner (2026-10-22)

## User decision
- Stoneapp code, login server and database MUST NOT be edited.
- No cookie banner, no visitor registration prompt or informational footer
  shown on Stoneapp itself.
- The user wants to recognize their own active browser and its generic
  actions under HYROVI Sec > HYROVI Smart > Hosts & Analytics.
- No covert identification of other visitors. Individual registration
  requires a real user action in the authenticated HPM dashboard.

## Production behavior
1. Logged-in HPM admin opens `https://hpm.hyrovi.com/security`, tab
   HYROVI Smart > Hosts & Analytics > Stoneapp.
2. Admin explicitly chooses "Diesen Browser registrieren" in HPM.
   The dashboard writes two separate secure SameSite=Lax first-party
   `.hyrovi.com` cookies for the *Stoneapp-specific tracker*:
   `hyrovi_stoneapp_analytics_consent=1` and
   `hyrovi_stoneapp_visitor_id=<random UUID>`. Their maximum age is
   90 days (browser privacy settings can shorten this).
   Both are set only in the admin's current browser. No POST of raw
   visitor ID from the HPM admin dashboard.
3. Opening Stoneapp in the SAME browser makes the existing NPM-proxy
   injected `/.well-known/hyrovi-analytics.js` record opted-in
   page view and coarse actions. The server stores only a hashed
   pseudonymous device key and permitted safe events (no input
   contents or passwords). The VPS opt-in event exporter then includes
   the visitor in HPM `/security/visitors` on Pi.
4. The admin can click "Registrierung deaktivieren" in HPM.
   The cookies are deleted from that browser; existing log records
   are not deleted retrospectively.
5. On Stoneapp, `showNotice()` returns immediately; no footer,
   popup, consent banner or any other tracker UI exists.
   A visitor WITHOUT the Stoneapp-specific cookies is anonymous.
   Existing global `hyrovi_analytics_consent` opt-in on *other*
   sites DOES NOT trigger Stoneapp profiling.
6. DNT or GPC block sending even for a registered browser. Other
   HYROVI host consent behavior is unchanged.

## Changes
- `backend/internal/visitor_consent_script.js`: Stoneapp-specific
  preference and random ID cookie names, no Stoneapp footer.
- `frontend/src/pages/Security/SmartHostsStudio.tsx`: explicit admin
  enrollment/deactivation controls under selected Stoneapp host, no
  credentials, identity assertions or form data.
- `tests/shared-cookie-consent.test.mjs`: existing cross-HYROVI
  opt-in/revocation tests preserved on normal hosts; Stoneapp zero-banner,
  isolated cookie namespace, registered page views, redaction, GPC/DNT
  and revocation tests added.

## Deployment
VPS HPM Compose:
`/opt/hyrovi-hpm-vps/runtime/docker-compose.yml`, mounts
`/opt/hyrovi-hpm-vps/runtime/browser-cookie-v3/visitor_consent_script_stoneapp_enroll_20261022.js`
to `/app/internal/visitor_consent_script.js`.
Rollback: `/opt/hyrovi-hpm-vps/runtime/docker-compose.before-stoneapp-enroll-20261022.yml`.

Pi HPM Compose: `/opt/hyrovi-hpm/runtime/docker-compose.yml`, mounts
`/opt/hyrovi-hpm/runtime/frontend-stoneapp-enroll-20261022` to
`/app/frontend` and
`/opt/hyrovi-hpm/runtime/backend-stoneapp-enroll-20261022/visitor_consent_script.js`
to `/app/internal/visitor_consent_script.js`.
Rollback: `/opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-stoneapp-enroll-20261022.yml`.

Both Compose services validated and HPM containers recreated. There
are NO changes to Stoneapp application source, data, or underlying
Stoneapp services; only proxy-injected JavaScript is different.

## Verification
- New VPS tracker publicly served Stoneapp JS from proxy has
  `const isStoneapp=...` and suppresses `showNotice()` on Stoneapp.
- Live Stoneapp login HTTPS 200; HPM 200; HYROVI One 200.
- Both local Pi and VPS HPM API 200 after deployment.
- New Vite frontend hashed asset HTTP 200; public index matches the
  new Pi static asset index.
- Node tests 15/15 passing, including simulated successful
  registration and event, DNT/GPC suppression, no footer before and
  after, no global consent auto-enrollment.
- TypeScript/Vite production build successful.
- **NOT yet verified as a real user profile**, since the user must
  themselves register their actual browser in HPM. An assistant
  running remotely cannot set their iPad browser cookie or claim
  to have recognized them. Full authenticated Safari tap test was not
  performed. Use actual Stoneapp after self-enrollment, then refresh
  Smart profiles; exporter uses bounded rolling logs.
