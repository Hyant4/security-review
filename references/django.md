# Django review reference

## Configuration and deployment

Inspect settings for each real environment, not only the development default. `python manage.py check --deploy` imports repository-controlled code. Run it with production-like settings only after separate code-execution authorization and inside the disposable sandbox defined by `SKILL.md`. It is a low-hanging-fruit check, not a code audit. If containment is unavailable, mark it **not assessed**.

Review:

- `DEBUG=False`, non-empty `ALLOWED_HOSTS`, secret management outside version control, and no sensitive configuration in client-visible assets.
- `SecurityMiddleware`, `CsrfViewMiddleware`, and `XFrameOptionsMiddleware` where applicable; middleware ordering; `SECURE_SSL_REDIRECT` or a documented trusted proxy equivalent.
- `SECURE_PROXY_SSL_HEADER` only when the proxy strips/sets the header so clients cannot forge it.
- HSTS rollout deliberately: start small, confirm every subdomain and asset is HTTPS-only before `includeSubDomains` or preload. HSTS is domain-wide and can lock out users.
- `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_REFERRER_POLICY`, frame policy, and CSP. Start a new CSP in report-only mode, examine reports, then enforce a minimal allowlist. Do not approve `unsafe-inline` or broad third-party origins without evidence.
- Secure cookies in HTTPS deployments: session and CSRF cookie scope/flags, appropriate `SameSite`, lifetime, rotation at login/privilege changes, and server-side invalidation needs.

## Views, templates, forms, APIs

Trace `request.GET`, `request.POST`, headers, files, URL parameters, serializer data, and task messages to their sinks. Prefer Django forms/serializers with explicit validation and ORM parameterization. Flag concatenated SQL, unsafe `RawSQL`/`extra`, `cursor.execute` with interpolated values, `mark_safe`, `safe`, custom template filters, untrusted `redirect`, `csrf_exempt`, unsafe deserialization, dynamic import/evaluation, user-controlled filesystem paths, and template rendering of untrusted content.

For Django REST Framework, inspect `DEFAULT_PERMISSION_CLASSES`, every view override, queryset filtering by authenticated tenant/owner, serializer writable fields, mass assignment, pagination/export endpoints, throttling scope, and authentication class ordering. Verify permissions in the view/service layer rather than relying on hidden UI buttons.

## Django features often missed

- Keep Django admin restricted, protect staff elevation, audit custom admin actions, and avoid exposing administrative data through autocomplete or exports.
- Do not let untrusted files become executable or directly serve them from a dangerous webroot. Use generated names and separate storage/serving policy.
- Review Celery/RQ/cron tasks as privileged entry points; validate message origin, tenant context, idempotency, and outbound URLs.
- Confirm cache, database, media storage, and debug tools are not public; treat cache keys and serialized cache values as an access-control surface.
- Review password hashers and auth backends before changing them. Avoid custom password handling; use Django mechanisms.

## Useful commands, with limits

The commands below execute target-controlled code or packages. They are examples for an explicitly authorized, disposable sandbox—not commands to run on the reviewer host. Use a read-only source mount, temporary writes, no host secrets, no production services, network disabled by default, and resource/time limits.

```text
python manage.py check --deploy
python manage.py test
python -m pip check
python -m pip list --outdated
```

Record the Python environment and settings module used. Dependency vulnerability tooling may require network access and an advisory database; distinguish unavailable tooling from a clean result.
