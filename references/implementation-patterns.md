# Security implementation patterns

Use these patterns when the user asks to fix findings. Inspect the target stack first; preserve its conventions and tests. Implement one control at a time and prove the protected flow still works.

## Endpoint policy

Create a policy table before editing code:

| Endpoint | Methods | Actor | Object/tenant rule | CSRF/auth | Rate scope | Side effect |
|---|---|---|---|---|---|---|

Enforce the table server-side. In Django use `require_http_methods`, `login_required`, `permission_required`, object-owner/tenant queryset filtering, and transactions where appropriate. In DRF set explicit authentication and permission classes, constrain `get_queryset()`, validate writable serializer fields, and give expensive actions named throttle scopes. Do not invent custom authentication or permission machinery where maintained framework controls fit.

Return `401` for missing/invalid authentication and `403` for an authenticated caller lacking permission. Avoid existence leaks: an object outside the caller's tenant may appropriately return `404`. Protect cookie-authenticated state changes with CSRF; do not solve webhook authentication with a blanket `csrf_exempt` alone.

## Rate limiting

Rate limits reduce abuse and resource exhaustion; they are not the only defense against credential attacks or denial of service.

1. Define a named scope per behavior (`login`, `password-reset`, `search`, `generate`, `upload`, `webhook`).
2. Prefer authenticated account/API-key identity. For anonymous traffic, use the directly connected address unless a trusted proxy has been configured and strips client-supplied forwarding headers.
3. Use a shared, atomic production backend. Django `LocMemCache` is process-local and cannot enforce a global limit across workers or serverless instances.
4. Layer burst and sustained limits where cost warrants it. Apply concurrency, payload-size, timeout, queue, and provider-budget controls separately.
5. Return `429` with `Retry-After`; keep the body generic. Derive logged/cache identities with a separate secret HMAC key, not a plain hash of a guessable IP/user ID and never a raw token.
6. Decide and document behavior when the limiter store fails. The included kits require an explicit `fail_closed=True` or `fail_closed=False` and emit a process-local rate-limited, metadata-only warning on store errors. Connect that event to shared metrics and alerting. Fail closed for especially sensitive/expensive operations only when availability requirements permit it.
7. Test allowed requests, the first blocked request, window reset, separation between identities/scopes, methods outside scope, and multi-worker behavior.

Choose the algorithm deliberately:

| Need | Starting design | Main caveat |
|---|---|---|
| Simple per-action budget | Fixed window | Boundary bursts can approach twice the nominal rate |
| Smooth sustained traffic | Sliding window or token bucket | More state/implementation complexity |
| Protect a scarce worker/provider | Concurrency semaphore plus queue cap | Must release safely on timeout/cancellation |
| Cost-varying GraphQL/generation | Weighted token bucket/quota | Cost model must be bounded and tested |

The reusable `assets/django-security-kit/rate_limit.py` implements a synchronous fixed-window decorator. Copy and adapt it rather than importing from the installed skill. It deliberately uses `REMOTE_ADDR` by default, requires a separate 32-byte-or-longer HMAC key, rejects a bare string such as `methods="POST"`, and refuses an unrecognized cache backend unless `require_shared_cache=False` is deliberately selected for isolated tests or after an independent backend review. It expects atomic `add`/`incr` behavior; confirm that property for the exact backend and version.

For DRF, prefer maintained throttle classes for ordinary API policy, but note that Django REST Framework documents its application-level throttling as non-atomic under concurrency. Use an edge/shared-store control when the limit is security- or cost-critical.

For FastAPI, adapt `assets/fastapi-security-kit/rate_limit.py` as a dependency on selected path operations or routers. Supply an authenticated-principal identity function when available, a separate random HMAC key from the application's secret store, a collection of complete HTTP method strings, and an explicit `fail_closed` decision. Its Redis Lua script makes increment plus expiry atomic, but fixed-window boundary bursts, Redis availability, eviction, key lifecycle, proxy trust, and edge protection remain deployment responsibilities.

For GraphQL, combine request rate with operation cost. Adapt `assets/graphql-security-kit/query_limits.py` before execution for byte, parser-token, expanded-selection, and structural bounds; use `parse_and_check_limits()` to reuse its parsed document when the framework permits, then run normal schema validation and variable coercion. `measure()` requires an explicit `QueryLimits` instance and is not an alternative to the byte-bounded entry point for raw input. Add schema-aware cost weights, pagination caps, execution/SQL timeouts, and per-operation/principal counters. A single request may contain aliases, fragments, batching, or a subscription and therefore cost far more than one ordinary REST call.

## Webhook endpoint

Implement the provider's exact signing scheme. The safe flow is:

1. Enforce POST and a small body limit at the edge/application server.
2. Read raw bytes once; verify signature and timestamp before parsing or causing side effects.
3. Use constant-time comparison, reject stale timestamps, and persist/deduplicate the provider event ID.
4. Allowlist event types and validate the schema.
5. Commit an idempotent state transition; enqueue slow work only after authentication and deduplication.
6. Return the provider-required status promptly. Log event ID, type, verification result, and processing outcome without secrets or full sensitive payloads.

Add tests for invalid signature, stale timestamp, duplicate event, unknown type, malformed JSON, valid event, handler retry, and a downstream failure. An HTTP `200` proves acknowledgement only—not delivery or completion of the external effect.

## SSRF-safe outbound endpoint

Prefer a fixed provider client or destination allowlist over a generic user-supplied URL fetcher. Resolve and validate every destination; restrict scheme/port; reject loopback, private, link-local, multicast, unspecified, and metadata ranges; re-check redirects; limit redirect count, time, and bytes; and apply network egress policy. Do not implement SSRF protection as a regex or hostname denylist alone.

## Rollout order

Add regression tests for registration, login, recovery, and the protected business action. Deploy rate limits in observable mode where practical, tune using real traffic, then enforce. Introduce CSP in report-only mode before enforcement. Roll out HSTS conservatively and verify all subdomains first.

For PostgreSQL, first inventory with the installed skill's `scripts/postgresql_security_audit.sql` resolved by absolute path, then change one layer at a time: create limited runtime roles, correct grants/default privileges, add and test RLS with the real runtime role, harden `SECURITY DEFINER` functions/search paths, and finally tighten network/TLS/authentication policy. Keep migrations under a separate owner role and test rollback/restoration before production changes.

Use migrations and placeholders appropriate to the project. A privileged-function change should be atomic: create or replace the function with an explicit safe path such as `SET search_path = trusted_app_schema, pg_temp`, schema-qualify its objects, revoke `EXECUTE` from `PUBLIC`, and grant it only to the intended runtime role in the same transaction. Never make the runtime role the table/function owner merely to bypass a grant problem.
