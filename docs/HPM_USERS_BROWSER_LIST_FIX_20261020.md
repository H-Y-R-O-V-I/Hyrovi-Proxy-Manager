# HPM Users browser list display fix, 2026-10-20

## Root cause
The previous Users list showed only individually consented device profiles.
Pi HPM production backend returned zero consented profiles but 62 browser
events and 26 page views from a bounded Pi/VPS log window, primarily
stoneapp.hyrovi.com and ai.hyrovi.com. The separate first-party Test
Studio correctly returned one test browser profile representing two sessions.
The front-end was not presenting those sources together.

## Fix
Users > Liste now displays separately:
1. Clickable Test Studio browser profiles with navigation to their merged
   test-session timeline, actions and diagnostic fields.
2. Reported browser activity grouped by host, with expandable individual
   nonidentifying browser events, host, time and safe route section.
3. Existing individually attributable opt-in visitor profiles, still shown
   as zero when no such profiles exist.

Host overview now prominently links to Browser-Besuche & Profile and
shows the observed browser event count and test-browser-profile count.
React Query refreshes the test profile summaries every 10 seconds while
host and visitor views are active.

No additional cross-site fingerprinting, permanent browser IDs, cookie
or silent user profiling was introduced. Anonymous events are not
represented as distinct human beings.

## Deployment
The production Vite/TypeScript build passed. Frontend assets were added
into the existing read-only Docker frontend-directory mount on Pi, at
/opt/hyrovi-hpm/runtime/frontend-all-hosts-20261020, and index.html
was replaced atomically after the new assets were fully copied.
The previous index was backed up:
 /opt/hyrovi-hpm/runtime/backups-users-20261020/index.before-browser-list-fix.html

Public HPM and its API, plus tests.hyrovi.com, returned HTTP 200.
Production JS bundle Security-g_RaO9z8.js contains the new UI strings.
HPM container remained running with 0 restarts. Backend live values:
62 anonymous browser events, 26 page views, test profiles 1,
consented browser profiles 0. Authenticated visual Safari verification
still requires the operator to open or reload the page.

## Limits
Browser events are not verified individual users. Persistent per-person
histories require a separate compliant, transparent login/session linkage;
the test-only session grouping remains scoped to tests.hyrovi.com.
