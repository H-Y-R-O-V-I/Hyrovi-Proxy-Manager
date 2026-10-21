# HYROVI HPM: unobtrusive cookie footer — LIVE on 2026-10-21

The original floating cookie choice has been replaced by a small in-flow
HTML footer at the end of document.body. It no longer uses CSS fixed
positioning, overlay cards or a modal.

The footer discloses that cookies may be used for website functions and
that the optional visitor analytics recognizes the same consenting browser
across .hyrovi.com subdomains for up to 90 days. A new visitor sees
Erlauben and Ablehnen as small equal-access options; optional visitor
tracking remains disabled before affirmative consent. After a choice
the footer displays the current setting and a small Cookie-Einstellungen
button to change it. Decline/revoke clears visitor and tab session IDs.
With GPC/DNT enabled it remains informational, with analytics disabled.

Production files and backups:
VPS active Compose /opt/hyrovi-hpm-vps/runtime/docker-compose.yml
VPS script /opt/hyrovi-hpm-vps/runtime/browser-cookie-v3/visitor_consent_script_v5.js
VPS backup /opt/hyrovi-hpm-vps/runtime/backups/docker-compose.before-cookie-footer-v5.yml
Pi active Compose /opt/hyrovi-hpm/runtime/docker-compose.yml
Pi script /opt/hyrovi-hpm/runtime/backend-users-20261020/internal/visitor_consent_script_v5.js
Pi backup /opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-cookie-footer-v5.yml

Verification: Node consent simulation passed. Public script on Stoneapp
and HYROVI AI contains footer rather than fixed positioning. Both
live HPM trackers reported sharedIdentityReady=true. Production HPM
API, Stoneapp login, HYROVI AI, HYROVI One and tests.hyrovi.com HTTP
200, both containers healthy and zero restarts.

The injection covers standard eligible HPM-proxied HTML pages, not the
HPM administrative site, HYROVI One or the isolated tests.hyrovi.com app.
A real Safari screenshot/visual test has not been completed.
