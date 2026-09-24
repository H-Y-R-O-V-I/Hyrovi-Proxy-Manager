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

## Rule templates

The HYROVI Sec UI includes conservative convenience templates for common patterns such as admin authentication denials, API authentication failures and admin write activity.

Templates do not create or enable a rule by themselves. Selecting a template only pre-fills the normal rule form. The operator can review or narrow the matchers before explicitly creating the rule.

The built-in templates currently use `observe` response mode. They therefore cannot trigger automatic rate limiting unless the operator deliberately changes the response mode to `soft` before creating the rule.

## Import and export

The rule UI can export a portable versioned JSON document and import it again.

Portable exports intentionally omit local rule IDs and creation/update timestamps. Imported rules are always normalized and validated again and receive new local metadata.

Current format:

```json
{
  "version": 1,
  "exportedAt": "2026-09-24T18:00:00.000Z",
  "rules": [
    {
      "name": "Sensitive admin API",
      "enabled": true,
      "score": 45,
      "response": "soft",
      "match": {
        "host": "one.hyrovi.com",
        "pathPrefix": "/api/admin",
        "pathContains": null,
        "methods": ["POST"],
        "statuses": [401, 403],
        "userAgentContains": null
      }
    }
  ]
}
```

Import modes:

- `merge`: keeps existing rules and adds only configurations that are not already present;
- `replace`: validates the complete import first, then replaces the existing rule set with newly generated local rule records.

The import rejects unsupported versions, invalid matchers, invalid response modes and imports that would exceed the global rule limit.

## Analytics and simulation

HYROVI Sec can evaluate custom rules against up to 1000 retained security events without changing enforcement state.

Existing-rule analytics report:

- matching retained events;
- unique source IPs and hosts;
- first and last observed hit;
- highest already-observed request risk;
- a bounded set of representative request samples.

Disabled rules are included. Their counts therefore answer “what would this rule have matched?” without enabling the rule.

The rule form also has a **Simulate** action. Simulation validates the current draft with the same matcher/score rules used for creation, evaluates it against retained events, and returns a bounded sample of matches.

Simulation is strictly read-only: it does not create a rule, change `detection-rules.json`, add risk to stored events, or create rate limits, challenges or blocks.

## Storage and API

Rules are stored in:

```text
/data/nginx/hyrovi-security/detection-rules.json
```

Admin endpoints:

```text
GET    /api/security/detection-rules
POST   /api/security/detection-rules
GET    /api/security/detection-rules/export
POST   /api/security/detection-rules/import
GET    /api/security/detection-rules/analytics
POST   /api/security/detection-rules/simulate
PUT    /api/security/detection-rules/<rule-id>
DELETE /api/security/detection-rules/<rule-id>
```

Read access, analytics and simulation use the normal Nginx Proxy Manager `logs:list` permission. Persistent mutations use `users:list`.

The HYROVI Sec page provides create, enable/disable and delete controls. Matching changes affect new live analysis immediately. Already archived security events retain the risk/signals that were recorded at the time, preserving historical explanations.

If the rule file becomes unreadable or invalid, HYROVI Sec logs the problem and continues built-in detection without custom rules instead of disabling the security monitor.
