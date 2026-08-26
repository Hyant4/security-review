# PostgreSQL security review

## Roles and privileges

Separate cluster/admin, schema-owner/migration, runtime read-write, runtime read-only, background worker, and reporting roles. The application runtime role must not be superuser, database/schema owner, `CREATEDB`, `CREATEROLE`, `REPLICATION`, or `BYPASSRLS`. Prefer group roles without `LOGIN` and narrowly scoped login roles; rotate credentials independently.

Review explicit and inherited memberships, default privileges, database/schema/table/sequence/function grants, and grants to `PUBLIC`. Revoke broad `CREATE` on shared schemas unless required. Qualify object names in migrations and privileged code.

## Row-level security

Use RLS as defense in depth for multi-tenant or per-user data where appropriate. Enable and, when the table owner must also be restricted, force RLS. Table owners, superusers, and `BYPASSRLS` roles can bypass policies; `TRUNCATE` and `REFERENCES` are outside row-security policy enforcement. Define both `USING` and `WITH CHECK` behavior for each command and test cross-tenant SELECT/INSERT/UPDATE/DELETE with the actual runtime role.

Avoid relying on a mutable session variable for tenant identity unless every pooled transaction sets, validates, and clears it safely. Transaction-pooling and leaked session state can cross tenant boundaries.

## SQL and functions

Parameterize values through the driver/ORM. Identifiers, operators, sort direction, table/column names, and raw filter fragments cannot be safely parameterized as values; choose them from code allowlists and quote using driver facilities. Avoid string-formatted SQL, unsafe ORM raw expressions, multi-statement execution, and database error leakage.

Review every `SECURITY DEFINER` function. Its `search_path` must exclude schemas writable by untrusted roles; put only required trusted schemas first and `pg_temp` last, and schema-qualify referenced objects. Revoke default `PUBLIC` execution where inappropriate, grant only the intended caller role, validate inputs, and minimize owner privileges. Apply revoke/grant in the same transaction as function creation. Treat any untrusted-writable schema in the effective path as a privileged code-execution risk.

## Connections, authentication, and availability

- Restrict network exposure and `listen_addresses`; use firewall/private networking in addition to PostgreSQL authentication.
- Review `pg_hba.conf` in order. Avoid `trust` and clear-text password authentication on untrusted networks. Current PostgreSQL documentation marks MD5 password support deprecated; prefer SCRAM where compatible.
- Require TLS for remote connections and validate the server certificate from clients (`verify-full` or provider equivalent where possible).
- Put credentials in a secret manager/environment, not URLs printed in logs, source, migrations, shell history, or client bundles.
- Bound pool size, connection acquisition, `statement_timeout`, `lock_timeout`, and idle transaction time. Avoid one process creating an unconstrained pool.
- Protect backups, WAL archives, replicas, exports, and database logs with the same data classification as the primary database. Test restoration and key access.

## Audit workflow

Run the installed skill's `scripts/postgresql_security_audit.sql` by absolute path with `psql` only on an authorized database. It starts a read-only transaction, records then replaces the inherited `search_path`, schema-qualifies catalog objects, and inventories roles, per-role/database settings, table/column/sequence usage grants, RLS, policies, privileged functions, extensions, and selected settings. Some catalog visibility depends on the caller, so missing rows are not proof of safety. Redact role names, network details, and policy expressions before sharing output externally.

Also inspect provider controls, `pg_hba.conf`, client TLS mode, secret storage, backup policy, connection pooler, and migration pipeline; SQL catalog queries cannot verify all of these.
