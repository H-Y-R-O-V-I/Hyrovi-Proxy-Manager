# HYROVI Sec Health and Diagnostics

HYROVI Sec exposes a read-only health view for operational troubleshooting.

## Admin endpoint

```text
GET /api/security/diagnostics
```

The endpoint uses normal Nginx Proxy Manager `logs:list` permission and returns metadata only.

It does not return request contents, cookies, Authorization headers, API keys, private keys, ingest tokens or alert-feed tokens.

## Disk health

HYROVI Sec measures the filesystem backing `/data/nginx/hyrovi-security`.

Status is:

- `critical` when free space is below 2 GiB or below 2%;
- `warning` when free space is below 5 GiB or below 10%;
- otherwise `ok`.

The dashboard shows used percentage, free/total bytes and the current status.

When storage is warning or critical, HYROVI Sec creates a best-effort operational alert. It checks at startup and every 15 minutes. An already-open alert at the same severity suppresses duplicate writes; after acknowledgement, a new alert can appear if storage is still unhealthy.

## Metadata included

The diagnostic response includes:

- live HYROVI Sec log size;
- response-action log size;
- retained proxy-event archive file count and bytes;
- retained app-event archive file count and bytes;
- presence/size/mtime of HYROVI Sec state files;
- whether generated Nginx hosts have the current instrumentation marker;
- emergency bypass state;
- automatic-response state and monitor interval;
- counts for active blocks, rate limits, challenges and escalations;
- total/enabled custom detection rules;
- open operational alerts;
- active/revoked trusted devices.

This makes disk exhaustion, missing instrumentation, disabled enforcement and abnormal state growth visible from the main HYROVI Sec page without exposing sensitive traffic data.
