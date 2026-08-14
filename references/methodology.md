# Methodology: evidence-led web security review

## Scope gate

Record the repository revision or deployed URL, authorized test accounts, environments, time window, permitted testing techniques, data-handling constraints, and third parties that are out of scope. Static/configuration review needs no live target authorization; active testing does.

Do not equate absence of evidence with security. Use these labels:

- **Verified**: direct reproducible evidence supports the conclusion.
- **Conditional**: a weakness or control depends on an unstated runtime condition.
- **Not assessed**: the asset, environment, or evidence was unavailable.

## Attack-surface worksheet

| Asset or flow | Entry point | Trust boundary | Sensitive data/action | AuthN/AuthZ | Abuse limit | Evidence |
|---|---|---|---|---|---|---|
| Route/API | method, path, parameters | browser/client to app | data/action | mechanism and owner check | key/store/window | file/line or test |
| Outbound call | URL, callback, integration | app to third party | credentials/data | service identity/scope | timeouts/quotas | config/code |
| Webhook | provider event | provider to app | state change | signature/replay/idempotency | intake limit | handler/config |
| Upload | multipart/object key | client to storage/processor | untrusted file | owner/access policy | size/count/scan | validator/storage |

Map public, authenticated, staff/admin, machine-to-machine, and scheduled paths. Trace user-controlled data through each boundary. Identify high-value actions: authentication and recovery, payment/commerce, user and tenant data, exports, privilege changes, destructive actions, content moderation, and actions that trigger external effects.

## Review order

1. Discover routes, entry points, settings, dependency files, deployment configuration, CI, and integration clients.
2. Map identities, authorization policy, object ownership/tenant scoping, tokens, and secrets.
3. Trace unsafe sinks: database, HTML, filesystem, network, parsers, redirects, templates, subprocesses, and logs.
4. Review availability controls and operational detection.
5. Validate selected high-risk hypotheses safely, within scope.
6. Score only after documenting exploitability, impact, preconditions, and evidence.

## Minimum control matrix

| Area | Review questions |
|---|---|
| Authentication | Are credentials protected, reset flows resistant to enumeration, sessions rotated and revoked appropriately, and brute-force resistance layered? |
| Authorization | Is every sensitive server-side action denied by default and object/tenant scoped? |
| Input/output | Are inputs constrained and encoded/parameterized for their exact sink? |
| SSRF | Can any untrusted URL reach internal or cloud metadata addresses, alternate schemes, or redirects? |
| Secrets | Are credentials absent from source, logs, builds, client bundles, and error pages; are rotation and least privilege feasible? |
| Dependencies | Are direct/transitive dependencies locked, supported, checked for advisories, and updated through a tested process? |
| Headers/TLS | Are transport, framing, MIME, referrer, CSP, and proxy assumptions appropriate to the deployment? |
| Logging | Are security events useful and protected without leaking credentials, tokens, personal data, or unsafe untrusted strings? |

## Safe validation

Use test accounts and harmless values. Prefer a single controlled request or a unit/integration test over enumeration, fuzzing, credential guessing, mass downloading, or destructive payloads. Stop if an unexpected effect, data exposure, or third-party boundary is reached; preserve only redacted evidence and report it.
