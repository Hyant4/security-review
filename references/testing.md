# Security control testing

Test the claim made by a control, not only its happy path. Use isolated test data and an authorized environment. Keep load tests and active adversarial tests out of production unless the user explicitly authorizes their scope and impact.

## Endpoint and authorization matrix

For each sensitive endpoint/resolver, cover unauthenticated, authenticated wrong-role, wrong-owner/wrong-tenant, valid owner, privileged role, malformed input, duplicate/replay, and method/content-type variants. Verify both response and side effects. A `403` with an already-committed database change is a failed control.

Check inherited/router-level dependencies and permissions as well as local declarations. In FastAPI include `Annotated[..., Depends(...)]` and `Annotated[..., Security(...)]`; in Django/DRF include global defaults, class overrides, actions, queryset filtering, and serializer write controls. Confirm the runtime route/schema because static discovery is intentionally incomplete.

## Rate-limit contract

Test:

- Last allowed request, first `429`, `Retry-After`, remaining/reset headers, and reset behavior.
- Separation of identities, tenants, scopes, methods, and credentials.
- Concurrent increments against the exact shared backend; a sequential mock cannot prove atomicity.
- Multi-worker/multi-instance behavior and Redis/cache eviction or restart.
- Trusted-proxy normalization and resistance to client-supplied forwarding headers.
- Store outage under the chosen fail-open/fail-closed policy.
- Burst behavior at a fixed-window boundary plus sustained and concurrency limits.
- No raw token, email, user ID, or reversible plain hash in keys/logs.

## GraphQL contract

Test valid representative operations and separate failures for bytes, operations, variables, fragments, aliases, depth, field count, introspection, cycles, batching, and pagination. Then test schema validation, variable coercion, list cardinality/cost, resolver timeout, database statement timeout, and object/tenant authorization independently. Structural limits passing is not proof that a query is cheap or authorized.

## PostgreSQL contract

Parse/read-review audit SQL before use and execute it only against an authorized disposable or staging database first. Run privilege and RLS tests as the actual runtime role, not as the owner or a superuser. Include cross-tenant `SELECT`, `INSERT`, `UPDATE`, and `DELETE`; direct table access; sequence/function grants; pooled transaction state; and `SECURITY DEFINER` calls with attacker-controlled object names.

The included audit script is a read-only inventory. Its successful execution cannot prove TLS, `pg_hba.conf`, provider firewall, backup security, or absence of hidden catalog rows.

## Evidence and negative controls

Record the exact revision, dependency versions, configuration, backend, command, and redacted assertion. Include at least one negative control that would fail if the protection were removed or misconfigured. Label tests skipped because infrastructure or authorization was unavailable as **not assessed**, never as passed.
