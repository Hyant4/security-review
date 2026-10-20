from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from _support import ROOT, load_module


class InventoryTests(unittest.TestCase):
    def run_script(
        self,
        script: str,
        root: Path,
        *arguments: str,
        expect_success: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
        }
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / script), str(root), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            env=environment,
        )
        if expect_success and result.returncode != 0:
            self.fail(f"scanner failed: {result.stderr}")
        return result

    def test_json_has_relative_provenance_and_deterministic_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "api.py").write_text(
                'from fastapi import FastAPI\napp=FastAPI()\n@app.get("/health")\ndef health(): pass\n',
                encoding="utf-8",
            )
            arguments = ("--format", "json", "--root-label", "sample", "--revision", "abc123")
            first = json.loads(
                self.run_script("python_api_endpoint_inventory.py", root, *arguments).stdout
            )
            second = json.loads(
                self.run_script("python_api_endpoint_inventory.py", root, *arguments).stdout
            )
            self.assertNotIn("root", first)
            self.assertEqual(first["scan"]["root_label"], "sample")
            self.assertEqual(first["scan"]["revision"], "abc123")
            self.assertEqual(first["scan"]["snapshot_sha256"], second["scan"]["snapshot_sha256"])
            self.assertEqual(len(first["scan"]["snapshot_sha256"]), 64)
            self.assertNotIn(str(root), json.dumps(first))

    def test_python_inventory_detects_annotated_app_and_trace_route(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "api.py").write_text(
                "from fastapi import FastAPI\n"
                "app: FastAPI = FastAPI(docs_url=None)\n"
                "@app.trace('/diagnostics')\n"
                "def diagnostics(): pass\n",
                encoding="utf-8",
            )
            data = json.loads(
                self.run_script("python_api_endpoint_inventory.py", root).stdout
            )
            self.assertTrue(
                any(
                    item["kind"] == "FastAPI"
                    and item["symbol"] == "app"
                    and "docs_url=None" in item["controls"]
                    for item in data["signals"]
                )
            )
            self.assertTrue(
                any(
                    item["route_or_field"] == "/diagnostics"
                    and item["methods"] == ["TRACE"]
                    for item in data["signals"]
                )
            )

    @unittest.skipIf(os.name == "nt", "POSIX byte filenames required")
    def test_json_output_escapes_non_utf8_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            invalid_path = os.fsencode(root) + b"/invalid-\xff.py"
            descriptor = os.open(invalid_path, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                os.write(descriptor, b'(\n')
            finally:
                os.close(descriptor)
            result = self.run_script("python_api_endpoint_inventory.py", root)
            json.loads(result.stdout)
            self.assertIn(r"\udcff", result.stdout)

    def test_markdown_neutralizes_repository_controlled_structure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "api.py").write_text(
                'from fastapi import FastAPI\napp=FastAPI()\n'
                '@app.get("/safe\\n# INJECTED | `tick` <script> ![x](y) \\u202e")\n'
                'def endpoint(): pass\n',
                encoding="utf-8",
            )
            output = self.run_script(
                "python_api_endpoint_inventory.py", root, "--format", "markdown"
            ).stdout
            self.assertNotIn("\n# INJECTED", output)
            self.assertNotIn("<script>", output)
            self.assertNotIn("\u202e", output)
            self.assertIn("\\n# INJECTED", output)
            self.assertIn("&#124;", output)
            self.assertIn("&lt;script&gt;", output)

    def test_symlink_outside_root_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as external:
            root = Path(temp)
            target = Path(external) / "secret.py"
            target.write_text('@app.get("/outside")\ndef outside(): pass\n', encoding="utf-8")
            link = root / "linked.py"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink unavailable on this runner: {exc}")
            data = json.loads(
                self.run_script("python_api_endpoint_inventory.py", root, "--format", "json").stdout
            )
            self.assertFalse(data["scan"]["complete"])
            self.assertFalse(any(item["route_or_field"] == "/outside" for item in data["signals"]))
            self.assertTrue(any("symbolic-link" in item["error"] for item in data["parse_errors"]))

    def test_file_ast_and_output_budgets_report_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "large.py").write_text("x = 1\n" * 100, encoding="utf-8")
            data = json.loads(
                self.run_script(
                    "django_endpoint_inventory.py",
                    root,
                    "--max-file-bytes",
                    "20",
                ).stdout
            )
            self.assertFalse(data["scan"]["complete"])
            self.assertIn("file_byte_limit", data["scan"]["incomplete_reasons"])

            (root / "large.py").write_text(
                "\n".join(f'@app.get("/route-{index}")\ndef f{index}(): pass' for index in range(100)),
                encoding="utf-8",
            )
            output = self.run_script(
                "python_api_endpoint_inventory.py",
                root,
                "--max-output-bytes",
                "2500",
            ).stdout
            output_data = json.loads(output)
            self.assertLessEqual(len(output.encode("utf-8")), 2500)
            self.assertFalse(output_data["scan"]["complete"])
            self.assertIn("output_byte_limit", output_data["scan"]["incomplete_reasons"])

    def test_file_limit_stops_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.py").write_text("x=1\n", encoding="utf-8")
            (root / "b.py").write_text("x=2\n", encoding="utf-8")
            data = json.loads(
                self.run_script(
                    "python_api_endpoint_inventory.py", root, "--max-files", "1"
                ).stdout
            )
            self.assertEqual(data["scan"]["stats"]["files_scanned"], 1)
            self.assertIn("file_limit", data["scan"]["incomplete_reasons"])

    def test_invalid_utf8_counts_toward_total_byte_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for index in range(3):
                (root / f"invalid-{index}.py").write_bytes(b"\xff\xfe\xff\xfe")
            data = json.loads(
                self.run_script(
                    "python_api_endpoint_inventory.py",
                    root,
                    "--max-file-bytes",
                    "10",
                    "--max-total-bytes",
                    "6",
                ).stdout
            )
            self.assertEqual(data["scan"]["stats"]["bytes_scanned"], 4)
            self.assertIn("total_byte_limit", data["scan"]["incomplete_reasons"])

    def test_output_budget_uses_logarithmic_number_of_renders(self) -> None:
        common = load_module(
            "tested_inventory_common", ROOT / "scripts" / "_inventory_common.py"
        )
        calls = 0
        data = {
            "scan": {
                "complete": True,
                "incomplete_reasons": [],
                "stats": {"records_returned": 4_000, "records_omitted": 0},
            },
            "records": [{"value": "x" * 100} for _ in range(4_000)],
        }

        def render(value):
            nonlocal calls
            calls += 1
            return json.dumps(value)

        output = common.enforce_output_budget(
            data,
            ("records",),
            render,
            2_500,
            max_seconds=2.0,
        )
        self.assertLessEqual(len(output.encode("utf-8")), 2_500)
        self.assertLessEqual(calls, 20)
        self.assertIn("output_byte_limit", data["scan"]["incomplete_reasons"])

    def test_scan_limits_reject_non_finite_deadlines(self) -> None:
        common = load_module(
            "tested_inventory_common_limits", ROOT / "scripts" / "_inventory_common.py"
        )
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value), self.assertRaises(ValueError):
                common.ScanLimits(max_seconds=value)


if __name__ == "__main__":
    unittest.main()
