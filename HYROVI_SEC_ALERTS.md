# HYROVI Sec Alerts and HYROVI One Feed

HYROVI Sec maintains a bounded operational alert feed for security responses and high-severity application events.

## Alert sources

The initial alert sources are:

- automatic soft rate limit -> `medium`;
- adaptive challenge -> `high`;
- hard block -> `critical`;
- app/auth event with severity `high` or `critical` -> matching severity.

Alert persistence is best-effort. A storage problem in the alert subsystem is logged, but it does not stop rate limiting, challenges, blocking or app-event ingest.

## Storage

Alerts are stored in:

```text
/data/nginx/hyrovi-security/alerts.json
```

The file is limited to the most recent 1000 alerts.

Repeated open alerts with the same dedupe key inside five minutes update the existing alert and increment its `count` instead of producing unlimited duplicates.

Alerts have two states:

- `open`
- `acknowledged`

Acknowledgement is available from the HYROVI Sec admin UI and does not change the underlying enforcement state.

## Admin API

Normal Nginx Proxy Manager authentication and permissions protect:

```text
GET  /api/security/alerts
POST /api/security/alerts/<alert-id>/acknowledge
```

Useful list parameters:

```text
limit=100
status=open
since=2026-09-24T18:00:00.000Z
```

## HYROVI One read-only feed

The integration feed is disabled by default. Enable it with a dedicated secret:

```text
HYROVI_SEC_ALERT_FEED_TOKEN=<secret with at least 32 characters>
```

Then HYROVI One can pull:

```text
GET /api/security/integration/alerts?status=open&limit=100
Authorization: Bearer <HYROVI_SEC_ALERT_FEED_TOKEN>
```

The feed is read-only. It cannot acknowledge alerts, change policy, create blocks, remove blocks or otherwise modify HYROVI Sec.

The feed token is never returned by the API or UI. Comparison uses SHA-256 digests and Node's constant-time `timingSafeEqual`.

Example response:

```json
{
  "generatedAt": "2026-09-24T18:00:00.000Z",
  "alerts": [
    {
      "id": "example-id",
      "createdAt": "2026-09-24T17:59:00.000Z",
      "updatedAt": "2026-09-24T17:59:00.000Z",
      "status": "open",
      "severity": "critical",
      "type": "hard_block",
      "title": "Hard block applied to 203.0.113.25",
      "detail": "Challenge failed/ignored; high-confidence attack",
      "sourceIp": "203.0.113.25",
      "host": null,
      "app": null,
      "requestId": null,
      "entityId": "response-id",
      "count": 1
    }
  ]
}
```

No request bodies, cookies, Authorization headers, API keys or application secrets are added to alerts.
