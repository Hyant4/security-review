"""Shared safety boundaries for static endpoint inventory scripts."""

from __future__ import annotations

import ast
import hashlib
import html
import math
import os
import stat
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator


SCANNER_VERSION = "2.0"
_BIDI_CONTROLS = {
    0x061C,
    0x200E,
    0x200F,
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
}


@dataclass(frozen=True)
class ScanLimits:
    max_files: int = 5_000
    max_file_bytes: int = 1_048_576
    max_total_bytes: int = 52_428_800
    max_ast_nodes: int = 200_000
    max_records: int = 20_000
    max_errors: int = 100
    max_seconds: float = 30.0
    max_value_chars: int = 500
    max_output_bytes: int = 5_242_880

    def __post_init__(self) -> None:
        for name in (
            "max_files",
            "max_file_bytes",
            "max_total_bytes",
            "max_ast_nodes",
            "max_records",
            "max_errors",
            "max_value_chars",
            "max_output_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value < 1:
                raise ValueError(f"{name} must be positive")
        if isinstance(self.max_seconds, bool) or not isinstance(self.max_seconds, (int, float)):
            raise TypeError("max_seconds must be numeric")
        if not math.isfinite(float(self.max_seconds)) or self.max_seconds <= 0:
            raise ValueError("max_seconds must be positive and finite")


class ScanState:
    def __init__(self, limits: ScanLimits) -> None:
        self.limits = limits
        self.started = time.monotonic()
        self.files_considered = 0
        self.files_scanned = 0
        self.bytes_scanned = 0
        self.records_returned = 0
        self.records_omitted = 0
        self.errors: list[dict[str, str]] = []
        self.errors_omitted = 0
        self.incomplete_reasons: list[str] = []
        self.stop_requested = False
        self._manifest = hashlib.sha256()

    def mark_incomplete(self, reason: str, *, stop: bool = False) -> None:
        if reason not in self.incomplete_reasons:
            self.incomplete_reasons.append(reason)
        self.stop_requested = self.stop_requested or stop

    def check_time(self) -> bool:
        if time.monotonic() - self.started > self.limits.max_seconds:
            self.mark_incomplete("wall_clock_limit", stop=True)
            return False
        return True

    def add_error(self, rel: str, message: str) -> None:
        self.mark_incomplete("files_refused_or_unreadable")
        if len(self.errors) < self.limits.max_errors:
            self.errors.append(
                {
                    "file": bounded_text(rel, self.limits.max_value_chars),
                    "error": bounded_text(message, self.limits.max_value_chars),
                }
            )
        else:
            self.errors_omitted += 1
            self.mark_incomplete("error_limit")

    def add_records(self, target: list[Any], values: Iterable[Any]) -> None:
        values_list = list(values)
        room = max(self.limits.max_records - self.records_returned, 0)
        accepted = values_list[:room]
        target.extend(accepted)
        self.records_returned += len(accepted)
        omitted = len(values_list) - len(accepted)
        if omitted:
            self.records_omitted += omitted
            self.mark_incomplete("record_limit", stop=True)

    def add_manifest_entry(self, rel: str, content: bytes) -> None:
        self._manifest.update(rel.encode("utf-8", "surrogatepass"))
        self._manifest.update(b"\0")
        self._manifest.update(hashlib.sha256(content).digest())
        self._manifest.update(b"\n")

    def metadata(self, *, root_label: str, revision: str | None) -> dict[str, Any]:
        return {
            "scanner_version": SCANNER_VERSION,
            "root_label": bounded_text(root_label, self.limits.max_value_chars),
            "revision": bounded_text(revision, self.limits.max_value_chars) if revision else None,
            "snapshot_sha256": self._manifest.hexdigest(),
            "complete": not self.incomplete_reasons,
            "incomplete_reasons": list(self.incomplete_reasons),
            "limits": asdict(self.limits),
            "stats": {
                "files_considered": self.files_considered,
                "files_scanned": self.files_scanned,
                "bytes_scanned": self.bytes_scanned,
                "elapsed_seconds": round(time.monotonic() - self.started, 6),
                "records_returned": self.records_returned,
                "records_omitted": self.records_omitted,
                "errors_returned": len(self.errors),
                "errors_omitted": self.errors_omitted,
            },
        }


def _is_reparse(st: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(st, "st_file_attributes", 0) & marker)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def iter_python_files(
    root: Path,
    skip_dirs: set[str],
    state: ScanState,
) -> Iterator[tuple[Path, str]]:
    """Yield only lexical in-root candidates; opening is separately no-follow."""
    canonical_root = root.resolve(strict=True)
    folded_skips = {name.casefold() for name in skip_dirs}

    def walk_error(exc: OSError) -> None:
        state.add_error("<directory>", f"walk failed: {type(exc).__name__}")

    for directory, directory_names, file_names in os.walk(
        canonical_root, topdown=True, onerror=walk_error, followlinks=False
    ):
        if state.stop_requested or not state.check_time():
            return
        base = Path(directory)
        retained: list[str] = []
        for name in sorted(directory_names, key=str.casefold):
            if name.casefold() in folded_skips:
                continue
            candidate = base / name
            try:
                link_stat = os.lstat(candidate)
            except OSError as exc:
                rel = candidate.relative_to(canonical_root).as_posix()
                state.add_error(rel, f"directory metadata failed: {type(exc).__name__}")
                continue
            if stat.S_ISLNK(link_stat.st_mode) or _is_reparse(link_stat):
                rel = candidate.relative_to(canonical_root).as_posix()
                state.add_error(rel, "refused symbolic-link or reparse-point directory")
                continue
            if stat.S_ISDIR(link_stat.st_mode):
                retained.append(name)
        directory_names[:] = retained

        for name in sorted(file_names, key=str.casefold):
            if not name.casefold().endswith(".py"):
                continue
            if state.files_considered >= state.limits.max_files:
                state.mark_incomplete("file_limit", stop=True)
                return
            state.files_considered += 1
            candidate = base / name
            rel = candidate.relative_to(canonical_root).as_posix()
            yield candidate, rel


def read_python_source(
    path: Path,
    rel: str,
    root: Path,
    state: ScanState,
) -> str | None:
    """Open a regular in-root file without following links where supported."""
    if state.stop_requested or not state.check_time():
        return None
    canonical_root = root.resolve(strict=True)
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or _is_reparse(before):
            state.add_error(rel, "refused symbolic-link or reparse-point file")
            return None
        if not stat.S_ISREG(before.st_mode):
            state.add_error(rel, "refused non-regular file")
            return None
        if before.st_size > state.limits.max_file_bytes:
            state.add_error(rel, "file exceeds max_file_bytes")
            state.mark_incomplete("file_byte_limit")
            return None
        if state.bytes_scanned + before.st_size > state.limits.max_total_bytes:
            state.mark_incomplete("total_byte_limit", stop=True)
            return None
        resolved = path.resolve(strict=True)
        if not _inside(resolved, canonical_root):
            state.add_error(rel, "refused path outside repository root")
            return None

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                state.add_error(rel, "refused non-regular opened file")
                return None
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                state.add_error(rel, "file changed while opening")
                return None
            chunks: list[bytes] = []
            remaining = state.limits.max_file_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65_536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as exc:
        state.add_error(rel, f"file open failed: {type(exc).__name__}")
        return None

    if len(content) > state.limits.max_file_bytes:
        state.add_error(rel, "file exceeds max_file_bytes")
        state.mark_incomplete("file_byte_limit")
        return None
    if state.bytes_scanned + len(content) > state.limits.max_total_bytes:
        state.mark_incomplete("total_byte_limit", stop=True)
        return None
    state.files_scanned += 1
    state.bytes_scanned += len(content)
    state.add_manifest_entry(rel, content)
    try:
        source = content.decode("utf-8-sig")
    except UnicodeError as exc:
        state.add_error(rel, f"decode failed: {type(exc).__name__}")
        return None
    return source


def parse_bounded(source: str, rel: str, state: ScanState) -> ast.AST | None:
    try:
        tree = ast.parse(source, filename=rel)
        nodes = 0
        for nodes, _ in enumerate(ast.walk(tree), start=1):
            if nodes > state.limits.max_ast_nodes:
                state.add_error(rel, "AST exceeds max_ast_nodes")
                state.mark_incomplete("ast_node_limit")
                return None
        if not state.check_time():
            return None
        return tree
    except (MemoryError, RecursionError, SyntaxError) as exc:
        state.add_error(rel, f"parse failed: {type(exc).__name__}")
        return None


def bounded_text(value: object, maximum: int) -> str:
    text = str(value)
    if len(text) <= maximum:
        return text
    return text[:maximum] + f"...<truncated {len(text) - maximum} chars>"


def markdown_text(value: object, maximum: int = 500) -> str:
    """Render untrusted text on one inert Markdown line."""
    output: list[str] = []
    for char in bounded_text(value, maximum):
        code = ord(char)
        if char == "\n":
            output.append("\\n")
        elif char == "\r":
            output.append("\\r")
        elif char == "\t":
            output.append("\\t")
        elif (
            code < 0x20
            or code == 0x7F
            or 0xD800 <= code <= 0xDFFF
            or code in _BIDI_CONTROLS
        ):
            output.append(f"\\u{code:04x}")
        else:
            output.append(char)
    escaped = html.escape("".join(output), quote=True)
    return (
        escaped.replace("|", "&#124;")
        .replace("`", "&#96;")
        .replace("!", "&#33;")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
    )


def enforce_output_budget(
    data: dict[str, Any],
    record_keys: tuple[str, ...],
    render: Any,
    maximum: int,
    *,
    max_seconds: float | None = None,
) -> str:
    """Fit the artifact with logarithmic renders and a cooperative deadline."""
    scan = data["scan"]
    original_lists = {key: list(data.get(key, [])) for key in record_keys}
    total_records = sum(len(values) for values in original_lists.values())
    base_returned = int(scan["stats"]["records_returned"])
    base_omitted = int(scan["stats"]["records_omitted"])
    deadline = (
        time.monotonic() + max(float(max_seconds), 0.0)
        if max_seconds is not None
        else None
    )

    def mark(reason: str) -> None:
        scan["complete"] = False
        if reason not in scan["incomplete_reasons"]:
            scan["incomplete_reasons"].append(reason)

    def apply_keep(keep: int) -> None:
        remaining = keep
        for key in record_keys:
            values = original_lists[key]
            count = min(len(values), remaining)
            data[key] = values[:count]
            remaining -= count
        removed = total_records - keep
        scan["stats"]["records_returned"] = max(base_returned - removed, 0)
        scan["stats"]["records_omitted"] = base_omitted + removed

    def out_of_time() -> bool:
        return deadline is not None and time.monotonic() > deadline

    if out_of_time():
        mark("wall_clock_limit")
        apply_keep(0)
        rendered = render(data)
        if len(rendered.encode("utf-8")) > maximum:
            raise RuntimeError("scan metadata exceeds max_output_bytes")
        return rendered

    rendered = render(data)
    if out_of_time():
        mark("wall_clock_limit")
        if len(rendered.encode("utf-8")) <= maximum:
            updated = render(data)
            if len(updated.encode("utf-8")) <= maximum:
                return updated
        apply_keep(0)
        rendered = render(data)
        if len(rendered.encode("utf-8")) > maximum:
            raise RuntimeError("scan metadata exceeds max_output_bytes")
        return rendered
    if len(rendered.encode("utf-8")) <= maximum:
        return rendered

    mark("output_byte_limit")
    low, high = 0, total_records
    best_keep = -1
    best_rendered = ""
    while low <= high:
        if out_of_time():
            mark("wall_clock_limit")
            apply_keep(0)
            best_rendered = render(data)
            best_keep = 0
            break
        middle = (low + high) // 2
        apply_keep(middle)
        candidate = render(data)
        if len(candidate.encode("utf-8")) <= maximum:
            best_keep = middle
            best_rendered = candidate
            low = middle + 1
        else:
            high = middle - 1
    if best_keep < 0:
        raise RuntimeError("scan metadata exceeds max_output_bytes")
    if out_of_time():
        mark("wall_clock_limit")
        apply_keep(0)
        best_rendered = render(data)
        best_keep = 0
    apply_keep(best_keep)
    if len(best_rendered.encode("utf-8")) > maximum:
        raise RuntimeError("scan metadata exceeds max_output_bytes")
    return best_rendered
