"""Bounded inbound-call provenance for security-relevant static flows.

This module does not change flow reachability decisions. It explains which statically
resolved callers can reach the first function in a supported flow, including class
constructors and MCP-server lifecycle roots that the v0.4 flow analyzer intentionally
does not treat as agent tools.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from horustrace.models import FlowPath, SourceLocation
from horustrace.source_context import classify_source_context, path_parts_match

MAX_INBOUND_PROVENANCE_DEPTH = 8
MAX_INBOUND_ENTRYPOINTS = 32
_CLI_DIRS = {"cli", "command", "commands"}
_MCP_LIFECYCLE_METHODS = {
    "__init__",
    "__aenter__",
    "start",
    "startup",
    "run",
    "serve",
    "lifespan",
}


@dataclass(slots=True)
class _Callable:
    key: str
    module: str
    name: str
    path: Path
    node: ast.FunctionDef | ast.AsyncFunctionDef
    imports: dict[str, str] = field(default_factory=dict)
    owner_class: str | None = None


def _module_name(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imports(tree: ast.Module) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                result[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name
    return result


def _collect_callables(root: Path, python_paths: list[Path]) -> dict[str, _Callable]:
    callables: dict[str, _Callable] = {}
    for path in sorted(python_paths):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        module = _module_name(path, root)
        imports = _imports(tree)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = f"{module}.{node.name}" if module else node.name
                callables[key] = _Callable(key, module, node.name, path, node, imports)
                continue
            if not isinstance(node, ast.ClassDef):
                continue
            for method in node.body:
                if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                prefix = f"{module}." if module else ""
                key = f"{prefix}{node.name}.{method.name}"
                callables[key] = _Callable(
                    key,
                    module,
                    method.name,
                    path,
                    method,
                    imports,
                    owner_class=node.name,
                )
    return callables


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


class _CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[ast.Call] = []

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def _calls(info: _Callable) -> list[ast.Call]:
    collector = _CallCollector()
    for statement in info.node.body:
        collector.visit(statement)
    return collector.calls


def _resolve_callee(
    info: _Callable,
    called: str,
    callables: dict[str, _Callable],
    unique_simple: dict[str, str],
) -> str | None:
    if "." not in called:
        imported = info.imports.get(called)
        if imported in callables:
            return imported
        if info.owner_class:
            prefix = f"{info.module}." if info.module else ""
            method = f"{prefix}{info.owner_class}.{called}"
            if method in callables:
                return method
        local = f"{info.module}.{called}" if info.module else called
        if local in callables:
            return local
        return unique_simple.get(called)

    if info.owner_class and called.startswith(("self.", "cls.")):
        method_name = called.split(".", 1)[1]
        prefix = f"{info.module}." if info.module else ""
        method = f"{prefix}{info.owner_class}.{method_name}"
        if method in callables:
            return method

    first, rest = called.split(".", 1)
    imported = info.imports.get(first)
    if imported:
        candidate = f"{imported}.{rest}"
        if candidate in callables:
            return candidate
    if called in callables:
        return called
    return None


def _reverse_callers(callables: dict[str, _Callable]) -> dict[str, set[str]]:
    simple: dict[str, list[str]] = {}
    for key, info in callables.items():
        simple.setdefault(info.name, []).append(key)
    unique_simple = {
        name: keys[0]
        for name, keys in simple.items()
        if len(keys) == 1
    }

    reverse: dict[str, set[str]] = {}
    for caller_key in sorted(callables):
        info = callables[caller_key]
        for call in _calls(info):
            called = _dotted(call.func) or (
                call.func.id if isinstance(call.func, ast.Name) else ""
            )
            if not called:
                continue
            callee = _resolve_callee(info, called, callables, unique_simple)
            if callee is not None and callee != caller_key:
                reverse.setdefault(callee, set()).add(caller_key)
    return reverse


def _root_chains(
    target: str,
    reverse: dict[str, set[str]],
) -> tuple[list[list[str]], bool]:
    chains: list[list[str]] = []
    truncated = False

    def visit(current: str, path: list[str], depth: int) -> None:
        nonlocal truncated
        if len(chains) >= MAX_INBOUND_ENTRYPOINTS:
            truncated = True
            return
        callers = sorted(reverse.get(current, set()) - set(path))
        if not callers:
            chains.append(list(reversed(path)))
            return
        if depth >= MAX_INBOUND_PROVENANCE_DEPTH:
            truncated = True
            chains.append(list(reversed(path)))
            return
        for caller in callers:
            visit(caller, [*path, caller], depth + 1)

    visit(target, [target], 0)
    return chains, truncated


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _entrypoint_kind(info: _Callable, root: Path) -> tuple[str, str]:
    relative_path = Path(_relative(info.path, root))
    context = classify_source_context(relative_path)
    if context in {"test", "example", "tutorial", "notebook", "template-generated"}:
        return context.replace("-", "_"), f"source_context:{context}"

    lowered_parts = {part.lower() for part in relative_path.parts}
    name = relative_path.name.lower()
    if (
        path_parts_match(lowered_parts, _CLI_DIRS)
        or name == "__main__.py"
        or name == "cli.py"
        or name.endswith("_cli.py")
    ):
        return "cli", "cli_source_path"

    if info.owner_class and info.name in _MCP_LIFECYCLE_METHODS:
        semantic = f"{info.module}.{info.owner_class}".lower()
        if "mcp" in semantic and "server" in semantic:
            return "mcp_server_lifecycle", "mcp_named_server_lifecycle"

    if info.owner_class and info.name == "__init__":
        return "constructor", "class_constructor"
    return "runtime_root", "static_reverse_call_root"


def _entrypoint_record(
    chain: list[str],
    callables: dict[str, _Callable],
    root: Path,
) -> dict[str, Any] | None:
    if not chain:
        return None
    key = chain[0]
    info = callables.get(key)
    if info is None:
        return None
    kind, basis = _entrypoint_kind(info, root)
    location = SourceLocation(
        info.path,
        line=getattr(info.node, "lineno", 1) or 1,
        column=(getattr(info.node, "col_offset", 0) or 0) + 1,
    )
    return {
        "kind": kind,
        "basis": basis,
        "function": key,
        "location": {
            "path": _relative(location.path, root),
            "line": location.line,
            "column": location.column,
        },
        "inbound_call_chain": chain,
    }


def annotate_flow_entrypoints(
    root: Path,
    python_paths: list[Path],
    flows: list[FlowPath],
) -> None:
    """Attach bounded inbound entrypoint evidence to supported flows."""
    callables = _collect_callables(root, python_paths)
    if not callables:
        return
    reverse = _reverse_callers(callables)

    for flow in flows:
        call_chain = flow.metadata.get("call_chain")
        if not isinstance(call_chain, list) or not call_chain:
            continue
        target = next(
            (
                item
                for item in call_chain
                if isinstance(item, str) and item in callables
            ),
            None,
        )
        if target is None:
            continue

        chains, truncated = _root_chains(target, reverse)
        entrypoints = [
            record
            for chain in chains
            if (record := _entrypoint_record(chain, callables, root)) is not None
        ]
        entrypoints.sort(
            key=lambda item: (
                item["kind"],
                item["function"],
                item["location"]["path"],
                item["location"]["line"],
            )
        )
        flow.metadata["inbound_entrypoints"] = entrypoints
        flow.metadata["inbound_entrypoint_kinds"] = sorted(
            {item["kind"] for item in entrypoints}
        )
        flow.metadata["inbound_provenance_truncated"] = truncated
