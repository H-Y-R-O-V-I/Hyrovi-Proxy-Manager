# HYROVI Sec Custom Detection Rules

HYROVI Sec supports bounded custom request-detection rules without arbitrary code or regular expressions.

## Safety model

Custom rules use literal matchers only. They cannot execute JavaScript, shell commands, templates or arbitrary regular expressions.

A rule has a rollout stage and a response mode.

Rollout stages:

- `preview`: stored and evaluated by analytics/simulation, but excluded from live request scoring and enforcement;
- `active`: participates in live request analysis;
- `paused`: retained for later reuse and analytics, but excluded from live request scoring and enforcement.

New rules and built-in templates default to `preview`. Promotion to `active` is an explicit operator action. Existing pre-stage rules remain backward compatible: legacy `enabled: true` becomes `active`, while `enabled: false` becomes `paused`.

Response modes apply only while a rule is active:

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
  "stage": "preview",
  "enabled": false,
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

Templates do not create a rule by themselves. Selecting a template only pre-fills the normal rule form. If saved without changing rollout, the resulting rule is created in `preview` and cannot change live request risk or enforcement.

The built-in templates currently use `observe` response mode and `preview` rollout by default. A template can affect live traffic only after an operator explicitly promotes it to `active`.

## Import and export

The rule UI can export a portable versioned JSON document and import it again.

Portable exports intentionally omit local rule IDs and creation/update timestamps. Imported rules are always normalized and validated again and receive new local metadata.

Current format:

```json
{
  "version": 2,
  "exportedAt": "2026-09-24T18:00:00.000Z",
  "rules": [
    {
      "name": "Sensitive admin API",
      "stage": "preview",
      "enabled": false,
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

Version 2 exports include the rollout `stage`. Version 1 exports remain import-compatible and map their legacy `enabled` flag to `active` or `paused`.

The import rejects unsupported versions, invalid stages, invalid matchers, invalid response modes and imports that would exceed the global rule limit.

## Analytics and simulation

HYROVI Sec can evaluate custom rules against up to 1000 retained security events without changing enforcement state.

Existing-rule analytics report:

- matching retained events;
- hits during the last hour and last 24 hours;
- a 24-bucket hourly hit trend;
- unique source IPs during the last 24 hours plus total unique IPs and hosts;
- first and last observed hit;
- highest already-observed request risk;
- a bounded set of representative request samples.

Preview and paused rules are included. Their counts therefore answer “what would this rule have matched?” without activating the rule. Future-dated or invalid timestamps are excluded from the recent 1h/24h trend windows.

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

The HYROVI Sec page provides preview-first creation plus Promote, Pause, Resume and Delete controls. Only `active` rules affect new live analysis. Already archived security events retain the risk/signals that were recorded at the time, preserving historical explanations.

If the rule file becomes unreadable or invalid, HYROVI Sec logs the problem and continues built-in detection without custom rules instead of disabling the security monitor.
