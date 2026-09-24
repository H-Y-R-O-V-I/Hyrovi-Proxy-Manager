# HYROVI Sec App Security Events

HYROVI Sec can accept security events from HYROVI applications so proxy traffic can later be correlated with authentication, session, account and device activity.

## Secure-by-default ingest

App-event ingest is disabled unless the backend process has:

```text
HYROVI_SEC_INGEST_TOKEN=<secret with at least 32 characters>
```

Applications send events to:

```text
POST /api/security/app-events/ingest
Authorization: Bearer <HYROVI_SEC_INGEST_TOKEN>
Content-Type: application/json
```

The configured token is never returned by the API or admin UI. Token comparison uses fixed-size SHA-256 digests with Node's constant-time `timingSafeEqual`.

The admin list endpoint remains protected by normal Nginx Proxy Manager admin permissions:

```text
GET /api/security/app-events
```

## Allowed event types

The initial allowlist is:

- `login_success`
- `login_failed`
- `permission_denied`
- `token_created`
- `token_revoked`
- `session_created`
- `session_revoked`
- `admin_endpoint_accessed`
- `device_registered`
- `device_removed`
- `password_changed`
- `account_locked`
- `suspicious_account_action`

Allowed severities are `info`, `low`, `medium`, `high` and `critical`.

## Stored fields

Only this allowlist is persisted:

- server-generated event ID
- event timestamp and receive timestamp
- event type
- app name
- severity
- reported client IP
- ingest source IP
- request ID
- host
- opaque account ID
- opaque session ID
- opaque device ID
- short reason

Extra JSON properties are discarded.

Do **not** send passwords, session cookies, access/refresh tokens, API keys, Authorization headers, request bodies or other secrets in any of these fields. Account/session/device values should be opaque internal identifiers rather than credentials.

Example:

```json
{
  "event_type": "login_failed",
  "app": "hyrovi-one",
  "severity": "medium",
  "ip": "203.0.113.25",
  "request_id": "c89c7f64e62c4f889bdce1a9d8dc251e",
  "account_id": "account_42",
  "device_id": "device_a7",
  "reason": "invalid_credentials"
}
```

The response is `202 Accepted` with the generated event ID and normalized timestamp.

## Storage and retention

Events are stored as bounded daily JSONL files under:

```text
/data/nginx/hyrovi-security/app-events/YYYY-MM-DD.jsonl
```

Each daily file is compacted when it reaches roughly 4 MiB. File retention follows the HYROVI Sec event-retention policy (default 14 days, configurable from 1 to 90 days).

The API accepts timestamps up to five minutes in the future and up to 90 days in the past. This prevents malformed clients from creating indefinitely retained future-dated files.
