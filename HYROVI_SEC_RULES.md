# HYROVI Sec Custom Detection Rules

HYROVI Sec supports bounded custom request-detection rules without arbitrary code or regular expressions.

## Safety model

Custom rules use literal matchers only. They cannot execute JavaScript, shell commands, templates or arbitrary regular expressions.

A rule can run in one of two response modes:

- `observe`: adds explainable risk to the request and UI only;
- `soft`: adds explainable risk and can make the request eligible for the normal automatic soft-rate-limit path.

Custom rules do **not** directly qualify a request for a hard block. High-confidence hard blocking remains tied to built-in attack signals and the adaptive challenge/escalation path.

HYROVI Sec tracks two scores internally:

- visible `risk`: built-in signals plus all matching custom rules;
- `automationRisk`: built-in signals plus only custom `soft` rules.

This prevents a high-scoring `observe` rule from indirectly enabling automatic enforcement.

## Limits

- maximum 100 rules;
- score from 1 to 60;
- maximum 16 HTTP methods per rule;
- maximum 32 HTTP statuses per rule;
- host/path/user-agent matcher lengths are bounded;
- wildcard hosts support only a leading `*.`, for example `*.hyrovi.com`.

## Matchers

All populated matchers in one rule must match.

Supported fields:

- exact host, or leading wildcard host;
- path prefix;
- literal path substring;
- one or more HTTP methods;
- one or more HTTP status codes;
- case-insensitive literal User-Agent substring.

At least one matcher is required.

Example:

```json
{
  "name": "Sensitive admin API",
  "enabled": true,
  "score": 45,
  "response": "soft",
  "match": {
    "host": "one.hyrovi.com",
    "pathPrefix": "/api/admin",
    "pathContains": null,
    "methods": ["POST", "PUT", "DELETE"],
    "statuses": [401, 403],
    "userAgentContains": null
  }
}
```

A hit appears as an explainable request signal:

```text
Custom rule: Sensitive admin API (+45)
```

## Storage and API

Rules are stored in:

```text
/data/nginx/hyrovi-security/detection-rules.json
```

Admin endpoints:

```text
GET    /api/security/detection-rules
POST   /api/security/detection-rules
PUT    /api/security/detection-rules/<rule-id>
DELETE /api/security/detection-rules/<rule-id>
```

Read access uses the normal Nginx Proxy Manager `logs:list` permission. Mutations use `users:list`.

The HYROVI Sec page provides create, enable/disable and delete controls. Matching changes affect new live analysis immediately. Already archived security events retain the risk/signals that were recorded at the time, preserving historical explanations.

If the rule file becomes unreadable or invalid, HYROVI Sec logs the problem and continues built-in detection without custom rules instead of disabling the security monitor.

## Import and export

The HYROVI Sec page can export all custom rules as versioned portable JSON and import them again in either `merge` or `replace` mode.

Export endpoint:

```text
GET /api/security/detection-rules/export
```

Import endpoint:

```text
POST /api/security/detection-rules/import
```

Exported rule entries intentionally omit local IDs and timestamps. Imports are fully revalidated and always receive new local metadata. Repeated `merge` imports deduplicate identical rule configurations. `replace` validates the entire incoming set before atomically replacing the existing rules.
