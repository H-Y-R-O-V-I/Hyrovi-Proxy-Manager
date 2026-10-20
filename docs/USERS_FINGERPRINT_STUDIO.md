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
