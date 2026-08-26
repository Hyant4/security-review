# FastAPI security review

## Endpoint inventory

Inventory every `FastAPI`/`APIRouter` path operation, mounted ASGI app, WebSocket, callback, webhook, docs/OpenAPI route, static/media mount, and background task. Run the installed skill's `scripts/python_api_endpoint_inventory.py` by absolute path as a static starting point. Importing the application to inspect `app.routes` or generate OpenAPI executes target-controlled code; do it only after separate authorization and inside the disposable sandbox defined by `SKILL.md`.

For each operation record method/path, request and response model, actor, OAuth/API-key scopes, dependency chain, object/tenant authorization, database transaction, external side effect, payload limit, timeout, and rate-limit scope. A `Depends()` declaration is only a signal: inspect the dependency and all sub-dependencies.

## Authentication and authorization

Use FastAPI `Security`/`Depends` to centralize authentication and enforce scopes, but keep object/tenant checks next to the loaded object or repository query. Validate JWT signature, allowed algorithm, issuer, audience, expiry, not-before, key rotation, and token type; decoding is not validation. Do not place bearer tokens in query strings. Keep password/token endpoints separately limited and make their errors resistant to enumeration.

Constrain response models so internal fields cannot leak. Constrain writable models so callers cannot set owner, tenant, role, billing, or moderation fields. Avoid merging arbitrary dictionaries into ORM models. Return consistent `401`, `403`, and tenant-safe `404` results without stack traces.

## Rate limits and resource controls

Use a shared atomic store and named scopes for login, token issuance, recovery, registration, search, generation, uploads, webhooks, GraphQL, and expensive exports. Prefer authenticated principal or API key; for anonymous callers, use `request.client.host` only after the ASGI server is configured to trust a narrow proxy allowlist. Never parse `X-Forwarded-For` directly in application code.

Adapt `assets/fastapi-security-kit/rate_limit.py` as a route dependency. Its Redis Lua operation increments and sets expiry atomically. Supply a secret-manager-backed `key_secret` of at least 32 random bytes so predictable IP/user identities are not stored as plain hashes. Rotate by changing the key prefix and accepting the intentional counter reset.

The included implementation uses a fixed window, which can permit a burst near a window boundary. Add a sustained limit or choose a sliding-window/token-bucket design when that behavior matters. Also add edge limits, body-size limits, request/DB/external-call timeouts, bounded concurrency/queues, and provider budgets. Test store failure according to the explicit fail-open/fail-closed policy.

## Middleware and deployment

- Configure `TrustedHostMiddleware` with real hostnames. Use HTTPS redirects only with correct proxy/TLS termination behavior.
- Trust forwarded headers only from known proxies; ensure direct application-server access is restricted when relying on proxy normalization.
- Set CORS to exact origins/methods/headers. Credentials and wildcard origins are not interchangeable; CORS is not authentication.
- Decide whether `/docs`, `/redoc`, and `/openapi.json` are public. Hiding documentation is not a substitute for endpoint authorization.
- Treat WebSockets separately: authenticate before accepting, re-check authorization for subscriptions/actions, limit message size/rate/connections, and handle token expiry/revocation.
- Do not use `BackgroundTasks` for unbounded or security-critical durable processing; authenticate and commit idempotent intent before enqueueing.

## Data and outbound calls

Use parameterized ORM/driver APIs and explicit transaction boundaries. Set pool size, acquisition timeout, statement timeout, and cancellation behavior. Bound uploads and JSON bodies before expensive parsing. For outbound HTTP, use fixed providers/allowlists, explicit connect/read/write/pool timeouts, redirect restrictions, response-size caps, and SSRF-aware destination validation.

Test dependency overrides carefully: ensure production startup cannot load a test/no-auth dependency. Review exception handlers and logs for tokens, authorization headers, SQL, request bodies, and personal data.
