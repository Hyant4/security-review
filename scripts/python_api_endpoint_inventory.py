#!/usr/bin/env python3
"""Inventory FastAPI routes and Python GraphQL resolver signals statically."""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SKIP_DIRS = {
    ".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".venv",
    "__pycache__", "node_modules", "site-packages", "venv",
}
HTTP_DECORATORS = {"get", "post", "put", "patch", "delete", "head", "options", "api_route", "websocket"}
GRAPHQL_DECORATORS = {"field", "mutation", "subscription"}
SENSITIVE_WORDS = {
    "admin", "auth", "callback", "export", "graphql", "invite", "login",
    "oauth", "password", "payment", "recover", "reset", "token", "upload", "webhook",
}


@dataclass
class Signal:
    framework: str
    kind: str
    symbol: str
    route_or_field: str
    methods: list[str]
    controls: list[str]
    sensitive_hint: bool
    file: str
    line: int


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return f"{dotted(node.func)}(...)"
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


def text(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def string_list(node: ast.AST | None) -> list[str]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [value for item in node.elts if (value := text(item))]
    value = text(node)
    return [value] if value else []


def dependency_signals(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    found: set[str] = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Call) and dotted(item.func).split(".")[-1] in {"Depends", "Security"}:
            found.add(dotted(item)[:200])
    return found


def keyword_controls(call: ast.Call) -> set[str]:
    controls: set[str] = set()
    for keyword in call.keywords:
        if keyword.arg in {
            "dependencies", "dependency_overrides_provider", "permission_classes",
            "authentication_classes", "extensions", "middlewares",
        }:
            controls.add(f"{keyword.arg}={dotted(keyword.value)[:180]}")
            controls.update(dependency_signals(keyword.value))
    return controls


def call_controls(call: ast.Call, function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    controls = keyword_controls(call)
    for default in [*function.args.defaults, *(item for item in function.args.kw_defaults if item)]:
        controls.update(dependency_signals(default))
    arguments = [
        *function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs,
    ]
    if function.args.vararg:
        arguments.append(function.args.vararg)
    if function.args.kwarg:
        arguments.append(function.args.kwarg)
    for argument in arguments:
        controls.update(dependency_signals(argument.annotation))
    for decorator in function.decorator_list:
        name = dotted(decorator).lower()
        if any(word in name for word in ("auth", "permission", "limit", "throttle", "scope")):
            controls.add(dotted(decorator)[:200])
    return sorted(controls)


class Visitor(ast.NodeVisitor):
    def __init__(self, rel_file: str) -> None:
        self.rel_file = rel_file
        self.signals: list[Signal] = []

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        found_graphql = False
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            target = call.func if call else decorator
            full_name = dotted(target)
            leaf = full_name.split(".")[-1]
            if leaf in HTTP_DECORATORS and call:
                route = text(call.args[0]) if call.args else None
                route = route or "<dynamic>"
                methods = [leaf.upper()]
                if leaf == "api_route":
                    methods_kw = next((kw.value for kw in call.keywords if kw.arg == "methods"), None)
                    methods = [item.upper() for item in string_list(methods_kw)] or ["<dynamic>"]
                controls = call_controls(call, node)
                lowered = f"{route} {node.name}".lower()
                self.signals.append(Signal(
                    framework="fastapi",
                    kind="websocket" if leaf == "websocket" else "path-operation",
                    symbol=node.name,
                    route_or_field=route,
                    methods=methods,
                    controls=controls,
                    sensitive_hint=any(word in lowered for word in SENSITIVE_WORDS),
                    file=self.rel_file,
                    line=node.lineno,
                ))
            if leaf in GRAPHQL_DECORATORS or any(
                marker in full_name.lower() for marker in ("strawberry.field", "strawberry.mutation", "strawberry.subscription")
            ):
                found_graphql = True
                field_name = node.name
                if call:
                    name_kw = next((text(kw.value) for kw in call.keywords if kw.arg == "name"), None)
                    positional_name = text(call.args[0]) if call.args else None
                    field_name = name_kw or positional_name or field_name
                controls = {
                    dotted(item)[:200]
                    for item in node.decorator_list
                    if any(word in dotted(item).lower() for word in ("auth", "permission", "limit", "scope"))
                }
                if call:
                    controls.update(keyword_controls(call))
                self.signals.append(Signal(
                    framework="graphql",
                    kind=leaf if leaf in GRAPHQL_DECORATORS else "field",
                    symbol=node.name,
                    route_or_field=field_name,
                    methods=[],
                    controls=sorted(controls),
                    sensitive_hint=leaf in {"mutation", "subscription"} or any(
                        word in field_name.lower() for word in SENSITIVE_WORDS
                    ),
                    file=self.rel_file,
                    line=node.lineno,
                ))
        if node.name.startswith("resolve_") and not found_graphql:
            field_name = node.name.removeprefix("resolve_")
            self.signals.append(Signal(
                framework="graphql",
                kind="resolver",
                symbol=node.name,
                route_or_field=field_name,
                methods=[],
                controls=[],
                sensitive_hint=any(word in field_name.lower() for word in SENSITIVE_WORDS),
                file=self.rel_file,
                line=node.lineno,
            ))
        self.generic_visit(node)

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            leaf = dotted(node.value.func).split(".")[-1]
            if leaf in {"FastAPI", "APIRouter", "GraphQLRouter"}:
                symbol = dotted(node.targets[0]) if node.targets else "<dynamic>"
                prefix = next((text(kw.value) for kw in node.value.keywords if kw.arg == "prefix"), None)
                controls = keyword_controls(node.value)
                for keyword in node.value.keywords:
                    if keyword.arg in {"docs_url", "redoc_url", "openapi_url"}:
                        controls.add(f"{keyword.arg}={dotted(keyword.value)[:180]}")
                self.signals.append(Signal(
                    framework="graphql" if leaf == "GraphQLRouter" else "fastapi",
                    kind=leaf,
                    symbol=symbol,
                    route_or_field=prefix or "<root>",
                    methods=[],
                    controls=sorted(controls),
                    sensitive_hint=bool(prefix and any(word in prefix.lower() for word in SENSITIVE_WORDS)),
                    file=self.rel_file,
                    line=node.lineno,
                ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        leaf = dotted(node.func).split(".")[-1]
        if leaf in {"include_router", "mount", "add_route", "add_api_route"}:
            route = text(node.args[0]) if node.args else None
            self.signals.append(Signal(
                framework="fastapi",
                kind=leaf,
                symbol=dotted(node.func),
                route_or_field=route or "<dynamic>",
                methods=[],
                controls=sorted(keyword_controls(node)),
                sensitive_hint=bool(route and any(word in route.lower() for word in SENSITIVE_WORDS)),
                file=self.rel_file,
                line=node.lineno,
            ))
        self.generic_visit(node)


def files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.py"):
        if not any(part in SKIP_DIRS for part in path.parts):
            yield path


def inventory(root: Path) -> dict[str, object]:
    signals: list[Signal] = []
    errors: list[dict[str, object]] = []
    scanned = 0
    for path in files(root):
        scanned += 1
        rel = path.relative_to(root).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=rel)
        except (OSError, UnicodeError, SyntaxError) as exc:
            errors.append({"file": rel, "error": f"{type(exc).__name__}: {exc}"})
            continue
        visitor = Visitor(rel)
        visitor.visit(tree)
        signals.extend(visitor.signals)
    unique = {
        (s.framework, s.kind, s.symbol, s.route_or_field, s.file, s.line): s
        for s in signals
    }
    ordered = sorted(unique.values(), key=lambda s: (s.file, s.line, s.framework, s.kind))
    return {
        "notice": "Static inventory only; generated routes, inherited dependencies, and runtime schema require confirmation.",
        "root": str(root.resolve()),
        "python_files_scanned": scanned,
        "signals": [asdict(item) for item in ordered],
        "parse_errors": errors,
        "review_hints": [
            "Resolve mounted routers/apps and inspect runtime OpenAPI/app.routes.",
            "Trace GraphQL fields to resolvers, authorization, database calls, pagination, and cost.",
            "Confirm controls listed as signals by reading their implementation and sub-dependencies.",
            "Check rate-limit identity against the trusted proxy model and a shared atomic store.",
        ],
    }


def markdown(data: dict[str, object]) -> str:
    lines = [
        "# Python API security inventory", "", f"> {data['notice']}", "",
        f"Python files scanned: {data['python_files_scanned']}", "",
        "| Framework | Kind | Route/field | Symbol | Methods | Controls | Sensitive hint | Evidence |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in data["signals"]:
        values = [str(item[key]).replace("|", "\\|") for key in ("route_or_field", "symbol")]
        lines.append(
            f"| {item['framework']} | {item['kind']} | `{values[0]}` | `{values[1]}` | "
            f"{', '.join(item['methods'])} | {', '.join(item['controls'])} | "
            f"{'yes' if item['sensitive_hint'] else 'no'} | `{item['file']}:{item['line']}` |"
        )
    if not data["signals"]:
        lines.append("| _No static FastAPI/GraphQL signals found_ | | | | | | | |")
    lines += ["", "## Review queue", ""]
    lines.extend(f"- {item}" for item in data["review_hints"])
    if data["parse_errors"]:
        lines += ["", "## Parse errors", ""]
        lines.extend(f"- `{item['file']}` — {item['error']}" for item in data["parse_errors"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path)
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
