# HYROVI Sec / Users / Alle Hosts — 2026-10-20

## Scope and default integration
All configured regular Pi/VPS HPM proxy hosts already use the central
proxy_host.conf and _location.conf Nginx templates. These include
the existing security access log, rate limiting, bot protections, and
the HPM first-party HTML analytics script location/insertion. There is no
need to rewrite generated Nginx config files to enable those features.
At audit: Pi 31/31 proxy hosts and VPS 15/15 carried both security log
and analytics-script location. The separately configured VPS test host
tests.hyrovi.com is counted as configured too. A single host may be
configured on more than one node; rows are host/node combinations.

## Change
HPM Sec > Users now opens Alle Hosts / Security Studio by default.
The UI contains all configured host/node entries even if no recent
log event exists, and includes unconfigured hosts only if recent log
events establish their presence. Operators can filter Pi/VPS, search,
sort activity by request/page count, errors, bot/tool markers or time,
and select any host to see detailed aggregate security counters,
sections and available anonymous VPS browser events.

The VPS Python aggregation service now inventories proxy-host
configs (plus the separately configured tests vhost) and exports rows
for idle configured hosts. The Pi JS backend inventories local config
with a 60-second TTL. New hosts are discovered automatically after
their existing proxy template has generated their config.
A host with zero recent log events is not necessarily offline.

## Boundaries
This change exposes only per-site/node operational event aggregates
and LOW-entropy HTTP header signature TYPE COUNTS. A signature is not
a verified device or person and cannot uniquely identify a browser.
The new multi-host UI never joins persons across sites or adds new
persistent browser IDs, hidden tracking, clickstream identities,
keylogging, sensitive form capture or cookies. The test-only
tests.hyrovi.com browser-profile experiment remains isolated.

Counts are based on bounded recent logs (Pi last 2 MiB, VPS bounded
recent log window) and are not full-lifetime metrics. The presence of
an analytics injection in Nginx config does not guarantee browser JS
execution (CSP, redirects, non-HTML and browser settings may differ).

## Production paths and rollback
VPS installed exporter:
 /usr/local/libexec/hyrovi-vps-hpm-activity-sync.py
VPS auto refresh:
 hyrovi-vps-hpm-activity-sync.timer (about every 60 seconds)
Pi backend read-only mount:
 /opt/hyrovi-hpm/runtime/backend-users-20261020/internal/security_visitors_v11.js
Pi frontend read-only mount:
 /opt/hyrovi-hpm/runtime/frontend-all-hosts-20261020
Pi Compose backup:
 /opt/hyrovi-hpm/runtime/backups-users-20261020/compose-pre-all-hosts-20261020.yml
Restore backup and recreate only HPM to rollback UI/API. Existing
certificates, proxy rules, DB, test-only services remain untouched.

## Verified
VPS exporter returned 16 configured host/node entries including tests
from 15 regular VPS proxies. Pi backend returned 31 configured proxy
entries, 47 configured entries across both nodes and 48 rows including
one host seen only in traffic. Pi backend direct list and testStudioList
methods load; HPM container running and restart count 0. Pi HPM public
API, public UI, HYROVI One and tests.hyrovi.com HTTP 200;
unauthenticated visitors API HTTP 403 as expected.
Production TypeScript/Vite build and backend JS syntax checks passed.
