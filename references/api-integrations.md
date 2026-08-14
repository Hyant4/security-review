# APIs, integrations, and operational controls

## APIs and authorization

For every API operation, determine authentication method, intended role, tenant/object policy, sensitive fields, rate-limit key, audit event, and error behavior. Check IDOR/BOLA by comparing a caller's permitted object against a controlled object they do not own; do not enumerate identifiers. Reject fields the caller is not allowed to set; validate pagination, filtering, sort fields, and bulk/export operations.

Store API keys and service credentials only in a secret manager or protected environment. Scope credentials to one service and capability where possible. Never return, log, or commit them. Require explicit timeouts, bounded retries, response-size limits, and error handling for third-party calls.

## Rate limiting and resource protection

Apply more than one layer: edge/WAF where available, application limits tied to account/API key and carefully trusted client address, per-action quotas, concurrency/time limits, and bounded work queues. Protect login, recovery, registration, invitation, search, expensive generation, exports, uploads, password/token verification, and webhook endpoints. In serverless/multi-instance systems, in-memory counters do not provide a global control; use an appropriate shared store or document the residual risk.

Return generic, consistent error responses; do not reveal whether an account, token, or object exists. Use retry guidance without revealing internal details.

## SSRF and outbound networking

Treat every URL, hostname, redirect destination, image fetch, import, preview, webhook callback, and proxy request as hostile. Prefer an allowlist of known domains and a dedicated egress path. Permit only required schemes and ports. Resolve hosts and reject loopback, private, link-local, multicast, unspecified, and cloud metadata addresses before connecting. Prevent time-of-check/time-of-use gaps by pinning the validated address or verifying the actual connected peer where the client permits it, and repeat validation for every redirect. Limit redirects, time, bytes, and response handling. Network egress controls remain necessary because application validation alone is brittle.

## Webhooks

Use the provider's current signing specification. Read raw request bytes before parsing; verify the signature with a constant-time comparison; validate timestamp/window and deduplicate event IDs. Accept only expected event types and schema versions. Authenticate the sender before changing state, make handlers idempotent, and place slow work on a queue after a fast acknowledgement only when provider semantics allow it. Log event ID and outcome, never the secret or full sensitive payload.

## OAuth 2.0 and OpenID Connect

Use Authorization Code with PKCE for applicable public/browser clients. Register exact redirect URIs—never route via arbitrary `next`, `redirect`, or wildcard destinations. Bind a high-entropy state value to the browser session; in OIDC, use and validate nonce. Validate authorization-server issuer, ID token signature using trusted keys and rotation behavior, audience/client ID, authorized party when relevant, expiration, and intended flow. Restrict scopes, protect refresh tokens, and do not treat an unverified JWT decode as validation. Avoid deprecated implicit flow and password grant designs.

## Uploads

Allow only the business-required extensions/types. Decode and validate names before extension checks; verify content/signature using a trusted parser, but do not treat MIME or magic bytes alone as sufficient. Generate storage names, set file/count/compressed-size limits, authorize upload and retrieval separately, protect from CSRF when cookie-authenticated, scan/sandbox where risk warrants it, and store outside the application webroot or on isolated object storage. Serve downloads with an appropriate content disposition and no active-content surprises.

## Logging and monitoring

Log security-relevant outcomes: authentication/recovery, authorization denial, privilege changes, token/key lifecycle, webhook verification, rate-limit action, sensitive exports, and configuration changes. Include timestamp, correlation/request ID, action, non-sensitive actor/object identifiers, and outcome. Do not log passwords, bearer tokens, cookies, secret values, complete authorization headers, raw sensitive bodies, or unnecessary personal data. Prevent log injection by structured logging and protect log access, retention, integrity, and alert routing.
