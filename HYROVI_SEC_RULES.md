# HYROVI Sec Custom Detection Rules

HYROVI Sec supports bounded custom request-detection rules without arbitrary code or regular expressions.

## Safety model

Custom rules use literal matchers only. They cannot execute JavaScript, shell commands, templates or arbitrary regular expressions.

A rule has a rollout stage and a response mode.

Rollout stages:

- `preview`: stored and evaluated by analytics/simulation, but excluded from live request scoring and enforcement;
- `active`: participates in live request analysis;
- `paused`: retained for later reuse and analytics, but excluded from live request scoring and enforcement.

New rules and built-in templates default to `preview`. New rules also default to a promotion gate, so they cannot be created directly as `active` until the configured evidence checks pass. Existing pre-stage rules remain backward compatible: legacy `enabled: true` becomes `active`, while `enabled: false` becomes `paused`.

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
  "version": 3,
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
      },
      "promotionGate": {
        "enabled": true,
        "minObservedHits": 5,
        "minReviews": 3,
        "minConfirmedAttacks": 1,
        "maxFalsePositivePercent": 20
      }
    }
  ]
}
```

Import modes:

- `merge`: keeps existing rules and adds only configurations that are not already present;
- `replace`: validates the complete import first, then replaces the existing rule set with newly generated local rule records.

Version 3 exports include the promotion gate. Version 2 exports include rollout stage but no gate; version 1 exports use the legacy `enabled` flag. Version 1/2 imports without gate metadata remain ungated.

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

## Rule-health reviews

Operators can classify retained rule-hit samples as:

- `confirmed_attack`;
- `expected`;
- `false_positive`.

Reviews are metadata only. They do not automatically change a rule's score, response mode, rollout stage or enforcement state.

The server accepts a review only when both the rule and retained request still exist **and** the request currently matches that rule. This prevents arbitrary request IDs from being attached to unrelated rules.

Stored review records contain only:

- a generated review ID;
- rule ID;
- request ID;
- verdict;
- created/updated timestamps.

They do not duplicate the request IP, host, path, headers, body or authentication data. Re-reviewing the same rule/request pair updates the existing review instead of creating a duplicate. Deleting a detection rule deletes its stored reviews.

The rule table shows stored review totals, while the review panel joins verdicts back onto the bounded retained match samples. Reviews can also be cleared.

## Promotion gates

A promotion gate is an optional server-enforced safety check for moving a rule from `preview` to `active`.

New rules default to:

- at least **5 observed retained matches**;
- at least **3 reviewed matches**;
- at least **1 confirmed attack** review;
- at most **20% false-positive reviews**.

The thresholds are configurable per rule and can be disabled explicitly. Zero is a valid threshold value.

The gate result is calculated from the same retained-event analytics and review metadata shown in the dashboard. Each criterion is returned as a separate pass/fail check, and the UI displays `GATE READY` or `GATE BLOCKED`.

For a gate-enabled preview rule:

- direct `PUT stage=active` is rejected;
- creating the rule directly as `active` is rejected;
- promotion must use the dedicated promote endpoint;
- the promote endpoint re-evaluates retained matches and reviews server-side immediately before persisting `active`.

Reviews never activate a rule automatically. They only contribute evidence to the gate; an explicit operator promotion action is still required.

Legacy rules and version 1/2 imports that do not contain promotion-gate metadata remain ungated for backward compatibility. Version 3 exports include the complete gate configuration.


## Storage and API

Rules and review metadata are stored in:

```text
/data/nginx/hyrovi-security/detection-rules.json
/data/nginx/hyrovi-security/rule-reviews.json
```

Admin endpoints:

```text
GET    /api/security/detection-rules
POST   /api/security/detection-rules
GET    /api/security/detection-rules/export
POST   /api/security/detection-rules/import
GET    /api/security/detection-rules/analytics
POST   /api/security/detection-rules/simulate
POST   /api/security/detection-rules/<rule-id>/promote
PUT    /api/security/detection-rules/<rule-id>/reviews/<request-id>
DELETE /api/security/detection-rules/<rule-id>/reviews/<request-id>
PUT    /api/security/detection-rules/<rule-id>
DELETE /api/security/detection-rules/<rule-id>
```

Read access, analytics and simulation use the normal Nginx Proxy Manager `logs:list` permission. Persistent mutations, including review verdicts, use `users:list`.

The HYROVI Sec page provides preview-first creation, editable promotion-gate thresholds, evidence status, plus Promote, Pause, Resume and Delete controls. Only `active` rules affect new live analysis. Already archived security events retain the risk/signals that were recorded at the time, preserving historical explanations.

If the rule file becomes unreadable or invalid, HYROVI Sec logs the problem and continues built-in detection without custom rules instead of disabling the security monitor.
