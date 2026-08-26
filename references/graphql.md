# GraphQL security review

## Model the real attack surface

The HTTP path `/graphql` is only a transport. Inventory every query field, mutation, subscription, resolver, custom scalar, directive, data loader, upload, and federation/entity resolver. Map each field to actor, object/tenant rule, data classification, database/external calls, pagination, and estimated cost.

Run the installed skill's `scripts/python_api_endpoint_inventory.py` by absolute path for static Python schema signals. Building or importing the schema executes target-controlled code; do it only after separate authorization and inside the disposable sandbox defined by `SKILL.md`. Otherwise record dynamically generated fields as **not assessed**.

## Authentication and authorization

Authenticate the request or connection once, but authorize at the resolver/service and object level. Parent-object access does not automatically authorize nested sensitive fields. Mutations need permission checks for the target object and every writable field. Scope data-loader cache keys by tenant/authorization context; never share cached objects across principals.

Use variables and typed inputs; do not construct SQL from field names, arguments, sort directions, or filter fragments. Allowlist sortable/filterable fields and cap page size. Return generic client errors and redact stack traces, SQL, internal service messages, and secrets from GraphQL `errors.extensions`.

## Query cost and denial-of-service

Enforce multiple independent budgets before execution:

- Maximum request bytes, parser tokens, expanded selections, and wall-clock time enforced outside the parser process.
- One operation per request unless batching is explicitly required and separately capped.
- Maximum selection depth, list depth, aliases, fields, fragments, variables, and self-reference.
- Schema-aware cost weights that multiply list cardinality and pagination arguments.
- Maximum page size, database statement time, resolver/external-call concurrency, and total execution time.

Adapt `assets/graphql-security-kit/query_limits.py` only as the structural first layer. It limits bytes, parser tokens, operations, fragments, variables, depth, fields, aliases, expanded selections, cycles, undefined/duplicate fragments, and introspection use; it cannot infer database or resolver cost or preempt CPU by itself. Run it in the request's outer time/resource budget. After structural parsing, run the framework's schema validation and variable coercion before execution. Add schema-aware weights and validate variables such as `first`, `last`, and nested page sizes.

## Rate limiting

Do not apply only one counter to `/graphql`. Key by authenticated principal/API key (or trusted normalized client address), operation name or trusted-document hash, and cost class. Charge the computed cost rather than only request count for expensive queries. Use distinct limits for mutations, login/token operations, introspection, anonymous traffic, subscriptions, and batch entries.

Reject anonymous operations when no operation name/hash can be safely classified. Persisted/trusted documents reduce arbitrary-query exposure but require a secure registration/deployment process and do not replace resolver authorization.

## Introspection, CSRF, and transport

Introspection is an operational decision, not the main security boundary. If disabled publicly, keep an authenticated developer path and verify tooling; if enabled, budget it separately. Avoid state-changing mutations over GET. For cookie-authenticated GraphQL, enforce CSRF with same-site cookies plus a server-validated token/custom-header/content-type policy. CORS alone does not prevent CSRF.

For subscriptions, authenticate the handshake and each operation, bind context to the connection, revalidate long-lived authorization/token expiry, limit concurrent subscriptions/events, and clean up disconnects. Validate upload type/size/count and isolate storage; multipart GraphQL uploads expand the attack surface.
