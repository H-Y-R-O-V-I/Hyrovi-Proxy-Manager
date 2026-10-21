# HYROVI Smart · HPM Security Aggregate Analysis

Deployed 2026-10-21 (Europe/Berlin) to Raspberry Pi 5 HPM, via VPS / ssh pi5.

## Scope
HYROVI Smart is a new, operator-only Security > Users > HYROVI Smart view.
It computes explainable per-host operational signals using *already-existing*
bounded aggregate counters in /security/visitors. It does not attempt to
identify physical devices or individuals, and does not create fingerprints,
cross-site IDs, cookies, JS collectors, or additional client-side permissions.

The Pi and VPS windows differ (bounded local Pi log tail versus VPS export);
the risk score is not a proof of an attack. No automatic blocks. It has
insufficient-sample states and conservatively explains HTTP errors, obvious
bot/tool user agent shares, and large write-request shares (informational).

## Files
- backend/internal/security_smart.js: pure scoring, bounded input
- backend/internal/security_visitors.js: reports automaticActivity.smart
- frontend/src/pages/Security/SmartStudio.tsx: operator UI
- frontend/src/pages/Security/UsersStudio.tsx / AllHostsStudio.tsx: navigation
- frontend/src/api/backend/securityVisitors.ts: types
- tests/security-smart.test.mjs: standalone regression tests

## Validation
- node --test tests/security-smart.test.mjs: 5/5 passed
- node --check backend/internal/security_smart.js and security_visitors.js: passed
- frontend npm run build: TypeScript + Vite passed
- Live Pi HPM: HTTP 200 local API and public site
- one.hyrovi.com: HTTP 200
- protected visitors endpoint for unauthenticated users: HTTP 403
- Direct container test: mode aggregate-security-only, 49 host rows,
  20 with sufficient samples, 16 flagged for manual review
- Production container stable immediately following restart; not a long-term stability claim
- Existing opt-in visitor list behavior preserved, no new consent bypass

## Runtime deployment / rollback
Live compose: /opt/hyrovi-hpm/runtime/docker-compose.yml on Pi.
Backup: /opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-smart-20261021.yml.

The live compose mounts:
- frontend-smart-20261021 -> /app/frontend
- backend-smart-20261021/security_visitors.js -> /app/internal/security_visitors.js
- backend-smart-20261021/security_smart.js -> /app/internal/security_smart.js

Previous compose continued to mount frontend-all-hosts-20261020 and
backend-users-20261020/internal/security_visitors_v11.js.

Rollback on Pi, if necessary:
```bash
cd /opt/hyrovi-hpm/runtime
cp backups-users-20261020/docker-compose.before-smart-20261021.yml docker-compose.yml
docker compose config -q
docker compose up -d --no-deps --force-recreate hpm
```

## What was deliberately NOT built
The user requested unconditional browser-based, cross-session device
fingerprinting without any ability for visitors to consent. That functionality
has not been built or activated. Such fingerprints cannot prove a unique
physical device, and forced tracking may be subject to ePrivacy/TDDDG consent
requirements. Authenticated or voluntarily linked cryptographic device keys
are a better basis for verifiable device continuity.
