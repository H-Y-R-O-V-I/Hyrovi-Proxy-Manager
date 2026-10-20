# HPM Users loading / backend OOM repair — 2026-10-20

## Symptom and root cause
Mobile Safari HPM Sec / Users / Overview stayed at Loading server activity with dashes and misleading zeros. HPM static HTML still served HTTP 200.
Pi backend repeatedly crashed with FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory, and core dumped, around 13:47–13:49 CEST.
The container image's s6 backend launcher hard-coded 250 MiB max V8 heap.
The security archive was ~168 MiB in 15 daily files, with analysis caps previously allowing 100k events and up to 32 MiB per day. The precise source of all accumulated heap usage has not been profiled conclusively.

## Fix
- s6 backend launcher maximum heap 250 -> 512 MiB.
- Security analysis event maximum 100k -> 15k.
- Live analysis scan maximum 32 -> 8 MiB.
- Per-day archive scan maximum 32 -> 4 MiB.
- Startup processed archive IDs maximum 100k -> 15k.
- Monitor now has in-flight guard to prevent overlapping runs when scans exceed a 5s interval.
- No existing security logs, archived requests, rules, proxy hosts or certificates removed.

Prod backend source mount:
  /opt/hyrovi-hpm/runtime/backend-stability-20261020/security.js
  -> /app/internal/security.js
Prod s6 launcher mount:
  /opt/hyrovi-hpm/runtime/backend-stability-20261020/backend-run
  -> /etc/s6-overlay/s6-rc.d/backend/run
Repo copy: ops/pi-hpm/backend-run-512.sh
Compose backup for rollback:
  /opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.pre-memory-stability.yml

## Frontend fix
- Visitor API queries time out at 12 seconds, including the legacy never-settling auth redirect path.
- Automatic query retry disabled in Users.
- Error messages include Retry button.
- Unloaded counters show dash instead of zero.
- Narrow/mobile screen buttons wrap.
Frontend production build served from Pi:
  /opt/hyrovi-hpm/runtime/frontend-browser-list-20261020
Index HTML rollback copy:
  /opt/hyrovi-hpm/runtime/backups-users-20261020/index.before-loading-fix.html

## Verification
- Node backend JavaScript syntax passes; frontend TypeScript+Vite production build passes.
- HPM public and Security frontend HTTP 200; new assets available.
- In-container direct analytics visitor list returned 441 requests on 16 websites and 0 consented visitor profiles in 16 ms at ~13:54 CEST (recent log tail).
- Node backend running at 512 MiB heap setting; ~176 MiB resident memory after ~2 minutes; no fresh OOM in that window. Longer-term stability unverified.
- Public unauthenticated /api/security/visitors returns HTTP 403 by design. Authenticated Safari verification remains pending.
- Browser-specific identity/timelines still require explicit opt-in; raw HTTP logs are aggregate site activity.
