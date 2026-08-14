---
name: security-review
description: Review and harden Django/FastAPI web apps, REST/GraphQL APIs, and PostgreSQL. Use for security audits, threat modeling, secure code review, or fixes involving endpoints, resolvers, auth, authorization, rate limits, RLS, SSRF/injection, uploads, secrets, webhooks, OAuth/OIDC, headers, dependencies, and logging.
---

# Security review

Perform an evidence-led, defensive audit. Establish scope and authorization before interacting with a running target. Prefer code, configuration, tests, dependency manifests, and non-invasive requests. Do not exploit a weakness, alter data, brute-force, scan third-party systems, or send callbacks unless the user explicitly authorizes the target and method.

Use OWASP ASVS 5.0 as the baseline and OWASP Top 10:2025 as a risk map. Treat framework defaults as helpful controls, never as proof that an application is secure.

## Start

1. State the assessed revision, environments, review type (static, configuration, authenticated test, or external test), assets in scope, and exclusions.
2. Read `references/methodology.md`. Build the attack-surface inventory before judging individual controls.
3. Inspect the smallest relevant set of files and obtain reproducible evidence. Label each conclusion as **verified**, **conditional**, or **not assessed**.
4. Read only the applicable reference files:
   - Django: `references/django.md`
   - FastAPI: `references/fastapi.md`
   - GraphQL: `references/graphql.md`
   - PostgreSQL: `references/postgresql.md`
   - APIs, third parties, webhooks, or OAuth/OIDC: `references/api-integrations.md`
   - Implementing fixes for endpoints, rate limits, webhooks, or API controls: `references/implementation-patterns.md`
   - Planning or validating security tests: `references/testing.md`
   - Finding scoring or final report: `references/reporting.md`
   - Canonical source links and version pinning: `references/sources.md`
5. Report findings with a safe reproduction description, affected asset, impact, remediation, verification step, and source/control mapping. Do not expose secrets, access tokens, session cookies, personal data, or live exploit payloads.

For Django/DRF repositories, run `python scripts/django_endpoint_inventory.py <repository> --format markdown` when static endpoint discovery would improve coverage. Treat its output as an inventory and review queue, not as proof of a vulnerability. Confirm every route against the resolved URL configuration and its view, middleware, permissions, and deployment settings.

For FastAPI or Python GraphQL repositories, run `python scripts/python_api_endpoint_inventory.py <repository> --format markdown`. Confirm generated and mounted routes at runtime and trace GraphQL fields to their resolver, object/tenant authorization, database query, and cost controls.

## Required review passes

### 1. Attack surface and trust boundaries

Inventory routes, methods, inputs, upload points, redirects, user-controlled URLs, administrative functions, background jobs, queues, storage, database/cache, external APIs, webhooks, auth providers, CI/CD, and runtime configuration. Mark every trust boundary: browser to app, app to data store, app to external service, and webhook provider to app.

For each sensitive action, identify actor, object, tenant/owner relation, authorization decision point, data classification, and abuse limit. Compare server-side authorization—not only UI visibility—across roles and object identifiers.

### 2. Identity and access control

Review registration, login, password reset, MFA where applicable, account recovery, session lifecycle, JWT/API-key issuance, logout/revocation, privilege changes, and protected endpoints. Check that errors do not enable account enumeration, credentials are not logged, tokens are not accepted from unsafe locations, and cookies have suitable `Secure`, `HttpOnly`, and `SameSite` properties.

Test authorization at the object and tenant level: read, create, update, delete, bulk actions, exports, admin actions, and indirect references. Require deny-by-default, server-side checks, least privilege, and re-authorization for sensitive operations.

### 3. Input, browser, and server-side safety

Trace untrusted data to HTML/templates, SQL/ORM/raw queries, shell/process calls, deserializers, file paths, redirect targets, templates, XML, and URL fetchers. Check validation at the boundary, output encoding in the destination context, parameterized database access, and safe APIs.

For SSRF, restrict schemes, resolve and validate destination addresses, block loopback/private/link-local and metadata destinations, pin or re-check the address used by the connection, revalidate every redirect, set time/size limits, and prefer a service-level allowlist plus network egress controls. For uploads, inspect `references/api-integrations.md` and check content-based validation, limits, storage isolation, authorization, and safe serving.

### 4. Availability, integrations, and operations

Evaluate layered rate limits for login, recovery, registration, expensive API/search/generation endpoints, uploads, and webhook intake. Ensure limits use a shared production store when the deployment is multi-process or serverless; document identity keys, proxy/IP trust assumptions, response behavior, and fail-open/fail-closed choice.

For every webhook, verify raw-body signature verification with a constant-time comparison, timestamp/replay protection, idempotency, event allowlisting, fast acknowledgement plus asynchronous processing where justified, and safe handling of retries. For OAuth/OIDC, validate issuer, audience/client ID, signature and key rotation, expiration, nonce/state, PKCE, exact registered redirect URIs, and least-privilege scopes.

Review secrets, dependency supply chain, security headers, TLS/proxy handling, logging, alerts, backups, error handling, and deployment configuration. Run available framework and dependency checks, but report their limits.

## Django-specific baseline

Read `references/django.md` when Django is present. At minimum, inspect `settings` by environment, middleware, URL routing, views, serializers/forms, permissions, templates, models/managers, admin, storage, tasks, and `requirements`/lock files. Run `python manage.py check --deploy` against production-like settings when safe and available; record both output and configuration assumptions.

Pay special attention to `DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, `SECURE_PROXY_SSL_HEADER`, HTTPS/HSTS rollout, cookie flags, CSRF exemptions, open redirects, raw SQL, `mark_safe`/`safe`, `pickle`/unsafe deserialization, user-controlled storage paths, cache exposure, and Django admin access.

When the user requests implementation, read `references/implementation-patterns.md`. Reuse `assets/django-security-kit/rate_limit.py` only after adapting the identity, scope, cache backend, proxy model, endpoint cost, and tests to the target. Never copy a generic control into production without validating its failure mode and multi-instance behavior.

## FastAPI, GraphQL, and PostgreSQL baseline

Read the matching reference file for each technology. For FastAPI, inspect every path operation, dependency/security scope, exception handler, middleware, proxy trust setting, OpenAPI exposure, WebSocket, background task, and request/response model. For GraphQL, inventory operations and resolvers—not only `/graphql`—and evaluate field/object authorization, query cost, depth, aliases, fragments, batching, pagination, introspection, subscriptions, and error leakage. For PostgreSQL, inspect runtime/migration/owner roles, grants, RLS and bypass conditions, `SECURITY DEFINER`, `search_path`, authentication/TLS, pooling, timeouts, SQL construction, backups, and logging.

When implementing FastAPI rate limits, adapt `assets/fastapi-security-kit/rate_limit.py`; it uses an atomic Redis Lua operation and keyed-HMAC identities, but still requires a secret key, a reviewed identity/proxy model, sustained/burst policy, and layered edge controls. For GraphQL query budgets, adapt `assets/graphql-security-kit/query_limits.py` and add schema validation, schema-aware field costs, variable validation, and pagination caps. Run `scripts/postgresql_security_audit.sql` only against an authorized database; it is read-only and may expose role/policy metadata in its output.

## Evidence rules

- Use precise file path and line number, request/response metadata, configuration key, test result, or dependency advisory as evidence.
- Never call a candidate issue “verified” based only on a pattern match. State the preconditions when behavior depends on deployment, proxy, database, identity provider, or feature flags.
- Map to an exact ASVS requirement ID only after verifying that ID against the named ASVS version. Otherwise cite the ASVS chapter/topic without inventing an identifier.
- Minimize and redact proof. A harmless role/object comparison is usually sufficient for authorization; do not retrieve unrelated records.
- Separate code review, configuration review, dependency analysis, and live testing. A passing HTTP 200, clean command, or webhook acknowledgement proves only that narrow observation.

## Deliverable

Use the report format in `references/reporting.md`. Begin with scope and executive summary, then a prioritized findings table, detailed findings, passed/observed controls, residual risks, and a remediation plan ordered by risk and dependency. Include explicit **not assessed** items and an evidence appendix.
