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

from _inventory_common import (
    ScanLimits,
    ScanState,
    bounded_text,
    enforce_output_budget,
    iter_python_files,
    markdown_text,
    parse_bounded,
    read_python_source,
)


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


def inventory(
    root: Path,
    *,
    limits: ScanLimits | None = None,
    root_label: str | None = None,
    revision: str | None = None,
) -> dict[str, object]:
    limits = limits or ScanLimits()
    state = ScanState(limits)
    root = root.resolve(strict=True)
    endpoints: list[Endpoint] = []
    controls: list[ViewControl] = []
    settings: list[SettingSignal] = []
    for path, rel in iter_python_files(root, SKIP_DIRS, state):
        source = read_python_source(path, rel, root, state)
        if source is None:
            continue
        tree = parse_bounded(source, rel, state)
        if tree is None:
            continue
        visitor = InventoryVisitor(rel)
        try:
            visitor.visit(tree)
        except (MemoryError, RecursionError) as exc:
            state.add_error(rel, f"AST visit failed: {type(exc).__name__}")
            continue
        state.add_records(endpoints, visitor.endpoints)
        state.add_records(controls, visitor.controls)
        state.add_records(settings, visitor.settings)
        if state.stop_requested:
            break
    endpoints.sort(key=lambda item: (item.file, item.line))
    controls.sort(key=lambda item: (item.file, item.line, item.symbol))
    settings.sort(key=lambda item: (item.file, item.line, item.name))
    hints = [
        "Resolve include() chains and router-generated actions statically; use runtime checks only in an authorized sandbox.",
        "Match routes to view controls, inherited permissions, and middleware manually.",
        "Review every sensitive_hint route for authentication, object authorization, CSRF, and abuse limits.",
        "Confirm the production cache is shared and atomic before trusting rate limits.",
    ]
    return {
        "notice": "Static inventory only; absence of a signal is not a vulnerability or proof of safety.",
        "scan": state.metadata(root_label=root_label or root.name, revision=revision),
        "python_files_scanned": state.files_scanned,
        "endpoints": [asdict(item) for item in endpoints],
        "view_controls": [asdict(item) for item in controls],
        "settings_signals": [asdict(item) for item in settings],
        "parse_errors": state.errors,
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
        f"Python files scanned: {data['python_files_scanned']} (complete: {data['scan']['complete']})",
        "",
        "## Endpoints",
        "",
        "| Route | View | Name | Kind | Sensitive hint | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for item in endpoints:
        route = markdown_text(item["route"])
        view = markdown_text(item["view"])
        name = markdown_text(item["name"] or "")
        kind = markdown_text(item["kind"])
        evidence = markdown_text(f"{item['file']}:{item['line']}")
        lines.append(
            f"| `{route}` | `{view}` | {name} | "
            f"{kind} | {'yes' if item['sensitive_hint'] else 'no'} | `{evidence}` |"
        )
    if not endpoints:
        lines.append("| _No static route declarations found_ | | | | | |")
    lines += ["", "## View and configuration signals", ""]
    for item in controls:
        values = markdown_text(", ".join(item["controls"]) or "no local security assignments found")
        methods = markdown_text(", ".join(item["methods"]) or "methods unresolved")
        symbol = markdown_text(item["symbol"])
        evidence = markdown_text(f"{item['file']}:{item['line']}")
        lines.append(f"- `{symbol}` — {methods}; {values} (`{evidence}`)")
    for item in settings:
        name = markdown_text(item["name"])
        summary = markdown_text(item["summary"])
        evidence = markdown_text(f"{item['file']}:{item['line']}")
        lines.append(f"- `{name}` — {summary} (`{evidence}`)")
    if not controls and not settings:
        lines.append("- No static control signals found.")
    lines += ["", "## Review queue", ""]
    lines.extend(f"- {hint}" for hint in data["review_hints"])
    if data["parse_errors"]:
        lines += ["", "## Parse errors", ""]
        lines.extend(
            f"- `{markdown_text(item['file'])}` — {markdown_text(item['error'])}"
            for item in data["parse_errors"]
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Django/DRF repository root")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path, help="Write output to this file")
    parser.add_argument("--root-label", help="Logical repository label; never an absolute path")
    parser.add_argument("--revision", help="Caller-supplied commit/tag or snapshot label")
    parser.add_argument("--max-files", type=int, default=ScanLimits.max_files)
    parser.add_argument("--max-file-bytes", type=int, default=ScanLimits.max_file_bytes)
    parser.add_argument("--max-total-bytes", type=int, default=ScanLimits.max_total_bytes)
    parser.add_argument("--max-ast-nodes", type=int, default=ScanLimits.max_ast_nodes)
    parser.add_argument("--max-records", type=int, default=ScanLimits.max_records)
    parser.add_argument("--max-errors", type=int, default=ScanLimits.max_errors)
    parser.add_argument("--max-seconds", type=float, default=ScanLimits.max_seconds)
    parser.add_argument("--max-output-bytes", type=int, default=ScanLimits.max_output_bytes)
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.error(f"not a directory: {args.root}")
    limits = ScanLimits(
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        max_ast_nodes=args.max_ast_nodes,
        max_records=args.max_records,
        max_errors=args.max_errors,
        max_seconds=args.max_seconds,
        max_output_bytes=args.max_output_bytes,
    )
    data = inventory(
        args.root,
        limits=limits,
        root_label=bounded_text(args.root_label or args.root.name, limits.max_value_chars),
        revision=args.revision,
    )
    render = (
        (lambda value: json.dumps(value, indent=2, ensure_ascii=True) + "\n")
        if args.format == "json"
        else markdown
    )
    rendered = enforce_output_budget(
        data,
        ("endpoints", "view_controls", "settings_signals"),
        render,
        limits.max_output_bytes,
        max_seconds=max(
            limits.max_seconds - float(data["scan"]["stats"]["elapsed_seconds"]), 0.0
        ),
    )
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
