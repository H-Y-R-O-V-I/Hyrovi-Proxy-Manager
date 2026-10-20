# HYROVI Sec / Users / Fingerprint Studio — 2026-10-20

Production Pi HPM: static frontend and backend file bind mounts in
/opt/hyrovi-hpm/runtime/docker-compose.yml.
Prior Compose backup:
/opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.pre-deploy.yml.

## Performance
Security Dashboard polling: 5s -> 20s, requests per fetch: 2000 -> 400.
Settings polling reduced; other tabs are not mounted until opened.

## Consent and recording
The injected HYROVI first-party script sends **no visitor events until
consent is explicitly granted**. Consent creates a random ID cookie on the
HYROVI domain for up to 90 days, shared across participating subdomains.
The server stores an HMAC of the ID, not its plaintext.
Do Not Track and Global Privacy Control are respected.
No high-entropy fingerprints, keystrokes, form values, passwords, full
URLs/query strings, screenshots or automatic click recording.

Website must explain tracking and expose a real opt-in/withdrawal UI;
it calls window.hyroviAnalytics.grantConsent() only after explicit opt-in
and window.hyroviAnalytics.revokeConsent() on withdrawal.
For safe, predefined action event names the owning app may call
window.hyroviAnalytics.trackAction("settings_open").
Do not place personal data into event/action names.

## Interface and endpoint access
HYROVI Sec > Users / Fingerprint Studio has a consenting visitor list,
website/session counts, approximate browser/platform/environment hints,
and recent timestamped action timeline.
GET /api/security/visitors requires logs:list.
GET /api/security/visitors/:id requires logs:list.
PUT /api/security/visitors/:id requires users:list and updates label/notes.
Labels are saved in the Pi HPM /data volume, separate from analytics log.
Visitor data is bounded by existing rolling analytics log retention.

## Limitations
This iteration shows events received by the **Raspberry Pi HPM instance**.
VPS HPM events are not aggregated yet. A browser hint is NOT a verified
person's identity. Only explicitly instrumented app actions appear.
Historical anonymous proxy traffic cannot be assigned retrospectively.

## Rollback
On Pi restore the saved Compose file to the runtime directory and recreate
only the hpm container with Docker Compose. Persistent /data and
/etc/letsencrypt volumes remain untouched.

## 2026-10-20: automatic consent-free site activity
HYROVI Sec > Users opens "Automatic Site Activity" by default.
This summary reads the existing Pi HPM HTTP security/access log, without
setting tracking cookies or assigning events to particular people.
Every Pi-HPM-proxied site appearing in the recent log can appear automatically.
Shown: request counts per domain, approximate HTML page requests, HTTP write
requests, 4xx/5xx errors, coarse five-minute latest activity, aggregated
first URL segments with auth/token/API segments restricted. URL queries, IPs,
user agents, request IDs and secrets are NOT in the new API response.
Two-MiB bounded log window and 60s UI refresh reduce load.
This cannot detect clicks with no HTTP request or identify individual persons.
The optional opt-in visitor ID profile remains a separate subview and is NOT
fed by this anonymous summary. VPS-only HPM logs remain outside this view.
A privacy notice/lawful basis may still be required for ordinary server logs.
