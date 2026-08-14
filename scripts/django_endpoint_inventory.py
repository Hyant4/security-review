#!/usr/bin/env python3
"""Inventory Django/DRF endpoints and nearby security controls without imports.

This is a static review aid. It does not resolve includes, middleware, inherited
permissions, runtime settings, or deployment controls, so its output is never
proof that an endpoint is safe or vulnerable.
"""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SKIP_DIRS = {
    ".git", ".hg", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".tox", ".venv", "__pycache__", "node_modules", "site-packages", "venv",
}
SENSITIVE_ROUTE_WORDS = {
    "admin", "auth", "callback", "export", "generate", "gerar", "invite",
    "login", "oauth", "password", "payment", "recover", "reset", "token",
    "upload", "webhook",
}
CONTROL_DECORATORS = {
    "csrf_exempt", "login_required", "permission_required", "ratelimit",
    "require_GET", "require_POST", "require_http_methods", "staff_member_required",
}
SECURITY_ASSIGNMENTS = {
    "authentication_classes", "permission_classes", "throttle_classes",
    "throttle_scope", "DEFAULT_AUTHENTICATION_CLASSES",
    "DEFAULT_PERMISSION_CLASSES", "DEFAULT_THROTTLE_CLASSES",
    "DEFAULT_THROTTLE_RATES", "CACHES", "RATELIMIT_USE_CACHE",
    "RATELIMIT_CACHE_PREFIX", "REST_FRAMEWORK",
}


@dataclass
class Endpoint:
    route: str
    view: str
    name: str | None
    kind: str
    file: str
    line: int
    sensitive_hint: bool


@dataclass
class ViewControl:
    symbol: str
    methods: list[str]
    controls: list[str]
    file: str
    line: int


@dataclass
class SettingSignal:
    name: str
    summary: str
    file: str
    line: int


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return f"{dotted_name(node.func)}(...)"
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def literal_text(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def safe_assignment_summary(name: str, node: ast.AST) -> str:
    if name == "CACHES":
        text = dotted_name(node)
        flags = []
        for marker in ("LocMemCache", "DummyCache", "RedisCache", "MemcachedCache"):
            if marker in text:
                flags.append(marker)
        return ", ".join(flags) if flags else "configured; inspect backend"
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return ", ".join(dotted_name(item) for item in node.elts)[:500]
    if isinstance(node, ast.Dict):
        keys = [literal_text(key) for key in node.keys]
        return "keys: " + ", ".join(key for key in keys if key)[:500]
    if isinstance(node, ast.Constant):
        return repr(node.value)[:200]
    return dotted_name(node)[:500]


class InventoryVisitor(ast.NodeVisitor):
    def __init__(self, rel_file: str) -> None:
        self.rel_file = rel_file
        self.endpoints: list[Endpoint] = []
        self.controls: list[ViewControl] = []
        self.settings: list[SettingSignal] = []
        self.definition_depth = 0

    def visit_Call(self, node: ast.Call) -> None:
        func = dotted_name(node.func).split(".")[-1]
        if func in {"path", "re_path"} and len(node.args) >= 2:
            route = literal_text(node.args[0]) or dotted_name(node.args[0])
            view = dotted_name(node.args[1])
            name = next(
                (literal_text(kw.value) for kw in node.keywords if kw.arg == "name"),
                None,
            )
            lowered = f"{route} {name or ''}".lower()
            self.endpoints.append(Endpoint(
                route=route,
                view=view,
                name=name,
                kind=func,
                file=self.rel_file,
                line=node.lineno,
                sensitive_hint=any(word in lowered for word in SENSITIVE_ROUTE_WORDS),
            ))
        elif func == "register" and len(node.args) >= 2:
            route = literal_text(node.args[0]) or dotted_name(node.args[0])
            view = dotted_name(node.args[1])
            basename = next(
                (literal_text(kw.value) for kw in node.keywords if kw.arg == "basename"),
                None,
            )
            self.endpoints.append(Endpoint(
                route=route,
                view=view,
                name=basename,
                kind="router.register",
                file=self.rel_file,
                line=node.lineno,
                sensitive_hint=any(word in route.lower() for word in SENSITIVE_ROUTE_WORDS),
            ))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        decorators = sorted({
            dotted_name(item).split(".")[-1].replace("(...)", "")
            for item in node.decorator_list
            if dotted_name(item).split(".")[-1].replace("(...)", "") in CONTROL_DECORATORS
        })
        if decorators:
            self.controls.append(ViewControl(
                symbol=node.name,
                methods=[],
                controls=decorators,
                file=self.rel_file,
                line=node.lineno,
            ))
        self.definition_depth += 1
        self.generic_visit(node)
        self.definition_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases = " ".join(dotted_name(base) for base in node.bases)
        looks_like_view = any(word in bases for word in ("APIView", "View", "ViewSet"))
        assignments: list[str] = []
        methods: list[str] = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.lower() in {
                "get", "post", "put", "patch", "delete", "head", "options",
                "list", "create", "retrieve", "update", "partial_update", "destroy",
            }:
                methods.append(item.name.upper())
            if isinstance(item, (ast.Assign, ast.AnnAssign)):
                targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                for target in targets:
                    name = dotted_name(target)
                    if name in SECURITY_ASSIGNMENTS:
                        assignments.append(name)
        if looks_like_view or assignments:
            self.controls.append(ViewControl(
                symbol=node.name,
                methods=sorted(methods),
                controls=sorted(set(assignments)),
                file=self.rel_file,
                line=node.lineno,
            ))
        self.definition_depth += 1
        self.generic_visit(node)
        self.definition_depth -= 1

    def _record_assignment(self, targets: Iterable[ast.AST], value: ast.AST, line: int) -> None:
        for target in targets:
            name = dotted_name(target)
            if name in SECURITY_ASSIGNMENTS:
                self.settings.append(SettingSignal(
                    name=name,
                    summary=safe_assignment_summary(name, value),
                    file=self.rel_file,
                    line=line,
                ))

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.definition_depth == 0:
            self._record_assignment(node.targets, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if self.definition_depth == 0 and node.value is not None:
            self._record_assignment([node.target], node.value, node.lineno)
        self.generic_visit(node)


def python_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.py"):
        if not any(part in SKIP_DIRS for part in path.parts):
            yield path


def inventory(root: Path) -> dict[str, object]:
    endpoints: list[Endpoint] = []
    controls: list[ViewControl] = []
    settings: list[SettingSignal] = []
    parse_errors: list[dict[str, object]] = []
    scanned = 0
    for path in python_files(root):
        scanned += 1
        rel = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=rel)
        except (OSError, UnicodeError, SyntaxError) as exc:
            parse_errors.append({"file": rel, "error": f"{type(exc).__name__}: {exc}"})
            continue
        visitor = InventoryVisitor(rel)
        visitor.visit(tree)
        endpoints.extend(visitor.endpoints)
        controls.extend(visitor.controls)
        settings.extend(visitor.settings)
    endpoints.sort(key=lambda item: (item.file, item.line))
    controls.sort(key=lambda item: (item.file, item.line, item.symbol))
    settings.sort(key=lambda item: (item.file, item.line, item.name))
    hints = [
        "Resolve include() chains and router-generated actions at runtime.",
        "Match routes to view controls, inherited permissions, and middleware manually.",
        "Review every sensitive_hint route for authentication, object authorization, CSRF, and abuse limits.",
        "Confirm the production cache is shared and atomic before trusting rate limits.",
    ]
    return {
        "notice": "Static inventory only; absence of a signal is not a vulnerability or proof of safety.",
        "root": str(root.resolve()),
        "python_files_scanned": scanned,
        "endpoints": [asdict(item) for item in endpoints],
        "view_controls": [asdict(item) for item in controls],
        "settings_signals": [asdict(item) for item in settings],
        "parse_errors": parse_errors,
        "review_hints": hints,
    }


def markdown(data: dict[str, object]) -> str:
    endpoints = data["endpoints"]
    controls = data["view_controls"]
    settings = data["settings_signals"]
    lines = [
        "# Django endpoint security inventory",
        "",
        f"> {data['notice']}",
        "",
        f"Python files scanned: {data['python_files_scanned']}",
        "",
        "## Endpoints",
        "",
        "| Route | View | Name | Kind | Sensitive hint | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for item in endpoints:
        route = str(item["route"]).replace("|", "\\|")
        lines.append(
            f"| `{route}` | `{item['view']}` | {item['name'] or ''} | "
            f"{item['kind']} | {'yes' if item['sensitive_hint'] else 'no'} | "
            f"`{item['file']}:{item['line']}` |"
        )
    if not endpoints:
        lines.append("| _No static route declarations found_ | | | | | |")
    lines += ["", "## View and configuration signals", ""]
    for item in controls:
        values = ", ".join(item["controls"]) or "no local security assignments found"
        methods = ", ".join(item["methods"]) or "methods unresolved"
        lines.append(f"- `{item['symbol']}` — {methods}; {values} (`{item['file']}:{item['line']}`)")
    for item in settings:
        lines.append(f"- `{item['name']}` — {item['summary']} (`{item['file']}:{item['line']}`)")
    if not controls and not settings:
        lines.append("- No static control signals found.")
    lines += ["", "## Review queue", ""]
    lines.extend(f"- {hint}" for hint in data["review_hints"])
    if data["parse_errors"]:
        lines += ["", "## Parse errors", ""]
        lines.extend(f"- `{item['file']}` — {item['error']}" for item in data["parse_errors"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Django/DRF repository root")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path, help="Write output to this file")
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error(f"not a directory: {args.root}")
    data = inventory(args.root)
    rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n" if args.format == "json" else markdown(data)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
