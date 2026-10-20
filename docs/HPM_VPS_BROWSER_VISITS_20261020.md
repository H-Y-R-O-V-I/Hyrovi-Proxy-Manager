# Stoneapp browser visits across Pi/VPS HPM: 2026-10-20

## Root cause
stoneapp.hyrovi.com is served by VPS HPM proxy-host id 3, not the unused
Pi HPM proxy-host id 19. VPS had 679 historical Stoneapp client events:
192 page_view events and 0 consented visitor profiles. The Pi UI only
read Pi logs. Browser JavaScript on Stoneapp was already running.

## Deployed federation
A VPS-only systemd timer hyrovi-vps-hpm-activity-sync.timer runs the
job in ops/vps_browser_activity_sync.py about once a minute. Installed
at /usr/local/libexec/hyrovi-vps-hpm-activity-sync.py, managed by a
systemd oneshot service. Source files are the bounded recent tails
of VPS /opt/nginx-proxy-manager/data/logs/hyrovi-sec.log and
hyrovi-analytics-events.log. The job creates per-domain aggregate
HTTP request, writes, failures, broad route sections and browser
page_view/scroll/engagement counts in a rolling 24h log window.

It never transfers raw IPs, user agents, cookies, unconsented sessions
or full HTTP requests from VPS to Pi. Only explicitly consented HMAC
visitor ID events can be included in visitor profiles; none exist now.
The VPS and Pi HMAC device IDs are NOT currently linked between nodes.

The summary is written atomically via SSH to the Pi:
 /opt/hyrovi-hpm/runtime/vps-hpm-sync/vps-hpm-activity.json
with mode 0600. Pi Docker bind-mounts this directory read-only at
/data/vps-hpm-sync; using a directory avoids stale inodes when files
are atomically replaced. Verified that Docker sees replacement live.

Backend: /opt/hyrovi-hpm/runtime/backend-users-20261020/internal/security_visitors_v5.js
Frontend: /opt/hyrovi-hpm/runtime/frontend-vps-visits-20261020
Compose backup:
 /opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.pre-vps-atomic-sync-fix.yml
The backend rejects VPS exports older than 10 minutes.

## UI
HYROVI Sec > Users > Uebersicht shows both VPS and Pi rows, source
badges and browser-script page view counts. Under Users > Liste there
is a table of anonymous browser visit counts by site. Individual named
browser profiles remain available only after explicit analytics consent.

## Verified
At ~14:38 CEST live Pi HPM backend reported Stoneapp VPS 5 browser
page events in the rolling 24h export, 540 HTTP requests, 27 combined
node/domain rows, 0 consented individuals. Backend API HTTP 200,
public HPM /security and HYROVI One HTTP 200; source file auto-sync
timer active. These browser events are not proof of unique people.
