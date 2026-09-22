"""Repository-level Python function bindings for normalized agent tools.

Adapters normalize framework constructs independently, which can lose the exact Python
function behind an imported or wrapped tool. This pass reconstructs only statically
supported bindings and records them as tool metadata + provenance for later analyses.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from horustrace.models import EvidenceFact, Graph, SourceLocation, Tool


@dataclass(frozen=True, slots=True)
class _FunctionTarget:
    qualified_name: str
    module: str
    name: str
    path: Path
    line: int
    column: int


@dataclass(slots=True)
class _Module:
    name: str
    path: Path
    imports: dict[str, str]
    functions: dict[str, _FunctionTarget]


def _module_name(root: Path, path: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve_relative_module(current: str, level: int, module: str | None) -> str:
    if level <= 0:
        return module or ""
    package = current.split(".")[:-1]
    climb = max(level - 1, 0)
    if climb:
        package = package[: max(0, len(package) - climb)]
    if module:
        package.extend(module.split("."))
    return ".".join(package)


def _imports(tree: ast.Module, module_name: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            base = _resolve_relative_module(module_name, node.level, node.module)
            for alias in node.names:
                if alias.name == "*":
                    continue
                target = ".".join(part for part in (base, alias.name) if part)
                result[alias.asname or alias.name] = target
        elif isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = alias.name
    return result


def _build_modules(root: Path, python_paths: list[Path]) -> dict[str, _Module]:
    modules: dict[str, _Module] = {}
    for path in sorted(set(python_paths)):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        module_name = _module_name(root, path)
        functions: dict[str, _FunctionTarget] = {}
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            qualified = f"{module_name}.{node.name}" if module_name else node.name
            functions[node.name] = _FunctionTarget(
                qualified_name=qualified,
                module=module_name,
                name=node.name,
                path=path.resolve(),
                line=getattr(node, "lineno", 1) or 1,
                column=(getattr(node, "col_offset", 0) or 0) + 1,
            )
        modules[module_name] = _Module(
            name=module_name,
            path=path.resolve(),
            imports=_imports(tree, module_name),
            functions=functions,
        )
    return modules


def _existing_provenance_binding(tool: Tool) -> str | None:
    prefix = "python_function="
    values = {
        fact.fact[len(prefix):]
        for fact in tool.provenance
        if fact.fact.startswith(prefix)
    }
    return next(iter(values)) if len(values) == 1 else None


def _candidate_targets(
    tool: Tool,
    module: _Module | None,
    functions_by_qualified: dict[str, _FunctionTarget],
    functions_by_name: dict[str, list[_FunctionTarget]],
) -> list[tuple[_FunctionTarget, str]]:
    candidates: list[tuple[_FunctionTarget, str]] = []

    explicit = tool.metadata.get("function_qualified_name") or _existing_provenance_binding(tool)
    if isinstance(explicit, str) and explicit in functions_by_qualified:
        candidates.append((functions_by_qualified[explicit], "existing_provenance"))

    names: list[str] = []
    metadata_function = tool.metadata.get("function")
    if isinstance(metadata_function, str) and metadata_function:
        names.append(metadata_function)
    if tool.name and tool.name not in names:
        names.append(tool.name)

    import_module = tool.metadata.get("import_module")
    if isinstance(import_module, str) and import_module:
        for name in names:
            qualified = f"{import_module}.{name}"
            if qualified in functions_by_qualified:
                candidates.append((functions_by_qualified[qualified], "import_module"))

    if module is not None:
        for name in names:
            local = module.functions.get(name)
            if local is not None:
                candidates.append((local, "local_definition"))
            imported = module.imports.get(name)
            if imported and imported in functions_by_qualified:
                candidates.append((functions_by_qualified[imported], "imported_alias"))

    if tool.location is not None:
        path = tool.location.path.resolve()
        for name in names:
            for target in functions_by_name.get(name, []):
                if target.path == path:
                    candidates.append((target, "source_location"))

    # Repository-resolved tools are created from concrete function definitions.
    # A globally unique simple name is therefore acceptable as a last exact-static
    # fallback. Do not apply this to generic/name-only adapter observations.
    if tool.metadata.get("repository_resolved") is True:
        for name in names:
            matches = functions_by_name.get(name, [])
            if len(matches) == 1:
                candidates.append((matches[0], "repository_unique_name"))

    deduplicated: dict[str, tuple[_FunctionTarget, str]] = {}
    for target, origin in candidates:
        deduplicated.setdefault(target.qualified_name, (target, origin))
    return list(deduplicated.values())


def _record_binding(tool: Tool, target: _FunctionTarget, origin: str) -> None:
    tool.metadata["function"] = target.name
    tool.metadata["function_module"] = target.module
    tool.metadata["function_qualified_name"] = target.qualified_name
    tool.metadata["function_path"] = str(target.path)
    tool.metadata["function_line"] = target.line
    tool.metadata["function_binding_origin"] = origin
    if tool.name != target.name:
        tool.metadata["function_reference_alias"] = tool.name

    fact = EvidenceFact(
        subject=tool.name,
        fact=f"python_function={target.qualified_name}",
        origin="resolved",
        location=SourceLocation(target.path, target.line, target.column),
    )
    if fact not in tool.provenance:
        tool.provenance.append(fact)


def enrich_python_tool_bindings(graph: Graph, root: Path, python_paths: list[Path]) -> None:
    """Attach exact Python function provenance to normalized tools when supportable."""
    root = root.resolve()
    modules = _build_modules(root, python_paths)
    modules_by_path = {module.path: module for module in modules.values()}
    functions_by_qualified = {
        target.qualified_name: target
        for module in modules.values()
        for target in module.functions.values()
    }
    functions_by_name: dict[str, list[_FunctionTarget]] = {}
    for target in functions_by_qualified.values():
        functions_by_name.setdefault(target.name, []).append(target)

    for tool in graph.all_tools():
        module = None
        if tool.location is not None:
            module = modules_by_path.get(tool.location.path.resolve())
        candidates = _candidate_targets(
            tool,
            module,
            functions_by_qualified,
            functions_by_name,
        )
        if len(candidates) == 1:
            target, origin = candidates[0]
            _record_binding(tool, target, origin)
        elif len(candidates) > 1:
            tool.metadata["function_binding_ambiguous"] = sorted(
                target.qualified_name for target, _ in candidates
            )
