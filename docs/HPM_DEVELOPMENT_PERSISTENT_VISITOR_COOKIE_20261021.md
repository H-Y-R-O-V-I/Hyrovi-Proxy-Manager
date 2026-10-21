# HYROVI HPM: development-only persistent visitor cookie test — 2026-10-21

A developer requested a safe way to test resuming the same visitor after
closing and reopening the browser, including on other HYROVI subdomains.

## Where it is
Only the Vite DEV frontend includes the lower-left panel
"Development · Besucher-Cookie" (via DevelopmentQueryTools.tsx).
The public production HPM UI deliberately does not contain the panel.

Start a frontend development build, e.g. from the frontend directory with:
  npm run dev

## Explicit testing flow
1. Open the Development panel in your OWN browser and click
   "90-Tage-Test-Cookie aktivieren". This opts in that browser and creates
   hyrovi_analytics_consent=1 plus a Secure SameSite=Lax persistent
   hyrovi_visitor_id cookie, expiring after up to 90 days.
2. Close the window/browser normally and reopen; click "Prüfen". The masked
   last six characters of the ID confirm it was reused. The full ID is not
   displayed in the panel. Running the activation a second time keeps a
   previously valid cookie ID rather than rotating it.
3. "Test-Cookie zurücksetzen" clears only the analytics ID and current
   hyrovi_sid, revoking test consent. Existing website login cookies remain.
4. If the Vite dev UI runs at localhost, the cookie is localhost-only.
   Cross-subdomain sharing is available when running DEV over HTTPS on a
   HYROVI origin, because the browser allows Domain=.hyrovi.com only there.

Each new tab/browser session still gets its own hyrovi_sid. It must NOT be
persisted, because that would merge distinct sessions into one. HPM's
user aggregation uses the reused, consented visitor ID, not that session ID.

## Safety
- Never auto-activate cookies from DEV panel opening or page load.
- Never force through Do Not Track or Global Privacy Control.
- Reject arbitrary sites and insecure HTTP on HYROVI domains.
- The test is intended for the operator's own browser only, not all visitors.
- This cannot copy cookies across different devices or private profiles.
- It does not create permission to track real users without consent.

## Verification
Frontend tests (5 cases): frontend/src/development/visitorCookie.test.ts
  cd frontend && npx vitest run src/development/visitorCookie.test.ts
Existing analytics test: node tests/shared-cookie-consent.test.mjs
Build: cd frontend && npm run build
Verified production dist lacks the text "90-Tage-Test-Cookie aktivieren".
No production deploy is necessary or appropriate for DEV-only controls.
