from __future__ import annotations

import re
import unittest

from _support import ROOT


class SkillContractTests(unittest.TestCase):
    def test_runtime_execution_requires_separate_authorization_and_sandbox(self) -> None:
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        for phrase in (
            "untrusted data",
            "separate explicit authorization",
            "source mounted read-only",
            "network disabled by default",
            "isolated test database",
            "--format json",
            "<absolute-skill-dir>",
        ):
            self.assertIn(phrase, skill)
        self.assertNotIn("--format markdown", skill)

    def test_postgresql_inventory_is_anchored_and_parseable(self) -> None:
        from pglast import parse_sql

        source = (ROOT / "scripts" / "postgresql_security_audit.sql").read_text(
            encoding="utf-8"
        )
        sql = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith(("\\", "--"))
        )
        statements = parse_sql(sql)
        kinds = {raw.stmt.__class__.__name__ for raw in statements}
        self.assertTrue(statements)
        self.assertLessEqual(
            kinds,
            {"SelectStmt", "TransactionStmt", "VariableSetStmt", "VariableShowStmt"},
        )
        anchor = source.index("SET LOCAL search_path = pg_catalog;")
        self.assertLess(anchor, source.index("SELECT "))
        for name in (
            "pg_settings",
            "pg_roles",
            "pg_auth_members",
            "pg_database",
            "pg_namespace",
            "pg_default_acl",
            "pg_db_role_setting",
            "pg_policy",
            "pg_class",
            "pg_policies",
            "pg_proc",
            "pg_extension",
            "pg_get_userbyid",
            "pg_get_function_identity_arguments",
            "to_jsonb",
            "unnest",
            "aclexplode",
            "acldefault",
        ):
            self.assertIsNone(
                re.search(rf"(?<!pg_catalog\.)\b{re.escape(name)}\b", source),
                msg=f"unqualified catalog name: {name}",
            )
        self.assertIn("information_schema.column_privileges", source)
        self.assertIn("information_schema.usage_privileges", source)


if __name__ == "__main__":
    unittest.main()
