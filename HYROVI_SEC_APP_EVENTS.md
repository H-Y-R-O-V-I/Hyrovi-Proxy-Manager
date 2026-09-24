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

## Trusted signed devices

As an alternative to the shared ingest token, a registered device can authenticate each event with an Ed25519 signature. The private key stays on the device. HYROVI Sec stores the public key, SHA-256 fingerprint, app scope and replay state.

Trusted devices are registered from the HYROVI Sec admin page. Each device must have at least one allowed app. Use `*` only when a device intentionally needs to submit events for every app.

Signed requests use these headers:

```text
X-Hyrovi-Device-ID: <device id>
X-Hyrovi-Device-Sequence: <positive monotonic integer>
X-Hyrovi-Device-Time: <unix time in milliseconds>
X-Hyrovi-Device-Signature: <base64 Ed25519 signature>
```

The signature message is UTF-8 text with five newline-separated fields:

```text
HYROVI-SEC-DEVICE-V1
<device id>
<sequence>
<unix time in milliseconds>
<SHA-256 hex of canonical JSON event body>
```

Canonical JSON recursively sorts object keys, preserves array order and omits properties whose value is `undefined`. Signatures are accepted only within a five-minute clock window.

Replay protection is persistent. A sequence must be strictly greater than the previously accepted sequence. An admin sequence reset creates a new reset epoch, so signatures created before that reset remain invalid even though the numeric counter starts again at 1. A revoked device ID can only be registered again with a different Ed25519 key.

If any device-signature header is present, HYROVI Sec treats the request as device-authenticated and fails closed on invalid or incomplete signatures rather than falling back to the shared token.

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

## Proxy correlation

HYROVI Proxy Manager forwards the Nginx request ID to upstream applications as:

```text
X-Hyrovi-Request-ID: <nginx request id>
```

HYROVI apps should copy that value into the app-event `request_id` field when the security event is associated with the current HTTP request. Request detail then correlates an exact request-ID match even if the application does not report a client IP.

For events without a request ID, HYROVI Sec can still correlate a reported client IP inside a bounded time window:

- request detail: same IP within ±5 minutes;
- attack-session detail: same IP within the session time window plus 60 seconds on each side.

Attack-session correlation also checks all proxy request IDs in the session timeline.

Existing generated custom-location configs are upgraded through the `instrumentation-v3` marker so the request-ID header is added without manually re-saving every Proxy Host.

## Storage and retention

Events are stored as bounded daily JSONL files under:

```text
/data/nginx/hyrovi-security/app-events/YYYY-MM-DD.jsonl
```

Each daily file is compacted when it reaches roughly 4 MiB. File retention follows the HYROVI Sec event-retention policy (default 14 days, configurable from 1 to 90 days).

Timestamp parsing has an absolute safety bound of five minutes in the future and 90 days in the past. Persistence is stricter: an event older than the currently configured HYROVI Sec retention window is rejected instead of recreating an already-expired daily archive file.
