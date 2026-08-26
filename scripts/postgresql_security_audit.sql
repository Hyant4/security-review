-- Read-only PostgreSQL security inventory. Run only on an authorized database.
-- Some rows are hidden from non-privileged callers; absence is not proof of safety.
\pset pager off
\set ON_ERROR_STOP on

BEGIN READ ONLY;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '3s';
-- Capture the caller's original value without resolving any database object.
SHOW search_path;
-- Never inherit an assessed database's name-resolution policy.
SET LOCAL search_path = pg_catalog;

SELECT pg_catalog.current_database() AS database_name,
       current_user AS current_role,
       session_user AS session_role,
       pg_catalog.current_setting('server_version') AS server_version;

SELECT name, setting, source
FROM pg_catalog.pg_settings
WHERE name IN (
  'listen_addresses', 'password_encryption', 'ssl', 'ssl_min_protocol_version',
  'search_path', 'row_security',
  'statement_timeout', 'lock_timeout', 'idle_in_transaction_session_timeout',
  'log_connections', 'log_disconnections', 'log_statement', 'log_min_duration_statement'
)
ORDER BY name;

SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb,
       rolcanlogin, rolreplication, rolbypassrls, rolconnlimit,
       rolvaliduntil, rolconfig
FROM pg_catalog.pg_roles
ORDER BY rolname;

SELECT member_role.rolname AS member_role,
       granted_role.rolname AS granted_role,
       memberships.admin_option,
       COALESCE((pg_catalog.to_jsonb(memberships)->>'inherit_option')::boolean, true) AS inherit_option,
       COALESCE((pg_catalog.to_jsonb(memberships)->>'set_option')::boolean, true) AS set_option
FROM pg_catalog.pg_auth_members AS memberships
JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = memberships.member
JOIN pg_catalog.pg_roles AS granted_role ON granted_role.oid = memberships.roleid
ORDER BY member_role.rolname, granted_role.rolname;

SELECT datname, pg_catalog.pg_get_userbyid(datdba) AS owner, datallowconn, datconnlimit, datacl
FROM pg_catalog.pg_database
WHERE datname = pg_catalog.current_database();

SELECT n.nspname AS schema_name,
       pg_catalog.pg_get_userbyid(n.nspowner) AS owner,
       n.nspacl
FROM pg_catalog.pg_namespace AS n
WHERE n.nspname NOT LIKE 'pg_toast%'
ORDER BY n.nspname;

SELECT table_schema, table_name, grantee, privilege_type, is_grantable
FROM information_schema.table_privileges
ORDER BY table_schema, table_name, grantee, privilege_type;

SELECT table_schema, table_name, column_name, grantee, privilege_type, is_grantable
FROM information_schema.column_privileges
ORDER BY table_schema, table_name, column_name, grantee, privilege_type;

SELECT object_type, object_schema, object_name, grantee, privilege_type, is_grantable
FROM information_schema.usage_privileges
ORDER BY object_type, object_schema, object_name, grantee, privilege_type;

SELECT routine_schema, routine_name, grantee, privilege_type, is_grantable
FROM information_schema.routine_privileges
ORDER BY routine_schema, routine_name, grantee;

SELECT COALESCE(role_settings.rolname, '<all roles>') AS role_name,
       COALESCE(database_settings.datname, '<all databases>') AS database_name,
       settings.setconfig
FROM pg_catalog.pg_db_role_setting AS settings
LEFT JOIN pg_catalog.pg_roles AS role_settings ON role_settings.oid = settings.setrole
LEFT JOIN pg_catalog.pg_database AS database_settings ON database_settings.oid = settings.setdatabase
ORDER BY role_name, database_name;

SELECT pg_catalog.pg_get_userbyid(d.defaclrole) AS owner,
       COALESCE(n.nspname, '<all schemas>') AS schema_name,
       d.defaclobjtype AS object_type,
       d.defaclacl AS default_acl
FROM pg_catalog.pg_default_acl AS d
LEFT JOIN pg_catalog.pg_namespace AS n ON n.oid = d.defaclnamespace
ORDER BY owner, schema_name, object_type;

SELECT n.nspname AS schema_name,
       c.relname AS table_name,
       pg_catalog.pg_get_userbyid(c.relowner) AS owner,
       c.relrowsecurity AS rls_enabled,
       c.relforcerowsecurity AS rls_forced,
       (SELECT count(*) FROM pg_catalog.pg_policy AS p WHERE p.polrelid = c.oid) AS policy_count
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, c.relname;

SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
FROM pg_catalog.pg_policies
ORDER BY schemaname, tablename, policyname;

SELECT n.nspname AS schema_name,
       p.proname AS function_name,
       pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,
       pg_catalog.pg_get_userbyid(p.proowner) AS owner,
       p.prosecdef AS security_definer,
       p.proleakproof AS leakproof,
       p.proconfig AS function_settings,
       EXISTS (
         SELECT 1
         FROM pg_catalog.unnest(COALESCE(p.proconfig, ARRAY[]::text[])) AS setting
         WHERE setting LIKE 'search_path=%'
       ) AS has_fixed_search_path,
       EXISTS (
         SELECT 1
         FROM pg_catalog.aclexplode(
           COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
         ) AS acl
         WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
       ) AS public_can_execute,
       p.proacl
FROM pg_catalog.pg_proc AS p
JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, p.proname;

SELECT extname, extversion, n.nspname AS schema_name
FROM pg_catalog.pg_extension AS e
JOIN pg_catalog.pg_namespace AS n ON n.oid = e.extnamespace
ORDER BY extname;

COMMIT;

-- Review pg_hba.conf separately and in order. Privileged reviewers may also run:
-- SELECT line_number, type, database, user_name, address, auth_method, options, error
-- FROM pg_hba_file_rules ORDER BY line_number;
