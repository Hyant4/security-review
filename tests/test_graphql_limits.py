from __future__ import annotations

import time
import unittest

from _support import ROOT, load_module


class GraphQLLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = load_module(
            "tested_graphql_limits",
            ROOT / "assets" / "graphql-security-kit" / "query_limits.py",
        )

    def test_normal_query_and_shared_fragment_metrics(self) -> None:
        metrics = self.mod.validate_query(
            "query Q { a { ...Shared } b { ...Shared } } "
            "fragment Shared on Thing { id }"
        )
        self.assertEqual(metrics.operations, 1)
        self.assertEqual(metrics.fragments, 1)
        self.assertEqual(metrics.fields, 4)
        self.assertEqual(metrics.max_depth, 2)
        self.assertGreaterEqual(metrics.expanded_selections, 6)

    def test_fragment_dag_is_rejected_in_bounded_time(self) -> None:
        query = "query Q { ...F0 }\n" + "\n".join(
            f"fragment F{index} on Query {{ ...F{index + 1} ...F{index + 1} }}"
            for index in range(18)
        )
        query += "\nfragment F18 on Query { terminal }"
        started = time.perf_counter()
        with self.assertRaisesRegex(self.mod.QueryLimitError, "field|selection"):
            self.mod.validate_query(query)
        self.assertLess(time.perf_counter() - started, 1.0)

    def test_invalid_fragment_graphs_are_rejected(self) -> None:
        cases = (
            ("query { ...Missing }", "undefined"),
            (
                "query { ...A } fragment A on Query { x } fragment A on Query { y }",
                "duplicate",
            ),
            ("query { ...A } fragment A on Query { ...B } fragment B on Query { ...A }", "cyclic"),
        )
        for query, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                self.mod.QueryLimitError, message
            ):
                self.mod.validate_query(query)

    def test_measure_requires_limits_and_enforces_all_counts(self) -> None:
        document, _ = self.mod.parse_and_check_limits("query A { x }")
        with self.assertRaises(TypeError):
            self.mod.measure(document)
        two_operations = self.mod.parse("query A { x } query B { y }")
        with self.assertRaisesRegex(self.mod.QueryLimitError, "operations"):
            self.mod.measure(two_operations, self.mod.QueryLimits(max_operations=1))

    def test_parser_token_and_structural_limits(self) -> None:
        query = "{ " + " ".join(f"f{index}" for index in range(30)) + " }"
        with self.assertRaises(self.mod.QueryLimitError):
            self.mod.validate_query(query, self.mod.QueryLimits(max_tokens=10))
        with self.assertRaisesRegex(self.mod.QueryLimitError, "depth"):
            self.mod.validate_query("{ a { b { c } } }", self.mod.QueryLimits(max_depth=2))
        with self.assertRaisesRegex(self.mod.QueryLimitError, "introspection"):
            self.mod.validate_query(
                "{ __schema { types { name } } }",
                self.mod.QueryLimits(allow_introspection=False),
            )

    def test_invalid_configuration_and_query_types(self) -> None:
        for kwargs in (
            {"max_bytes": 0},
            {"max_tokens": True},
            {"max_expanded_selections": -1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises((TypeError, ValueError)):
                self.mod.QueryLimits(**kwargs)
        with self.assertRaises(TypeError):
            self.mod.validate_query(123)


if __name__ == "__main__":
    unittest.main()
