from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from horustrace.models import Graph, Tool


@dataclass(frozen=True, slots=True)
class FunctionRef:
    key: str
    module: str
    name: str
    path: Path
    line: int


def _module_name(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _collect_functions(root: Path, python_paths: list[Path]) -> list[FunctionRef]:
    refs: list[FunctionRef] = []
    for path in sorted(python_paths):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        module = _module_name(path, root)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            key = f"{module}.{node.name}" if module else node.name
            refs.append(
                FunctionRef(
                    key=key,
                    module=module,
                    name=node.name,
                    path=path.resolve(),
                    line=getattr(node, "lineno", 1) or 1,
                )
            )
    return refs


def _unique(values: list[FunctionRef]) -> FunctionRef | None:
    by_key = {item.key: item for item in values}
    return next(iter(by_key.values())) if len(by_key) == 1 else None


def _suffix_matches(refs: list[FunctionRef], candidate: str) -> list[FunctionRef]:
    return [
        ref
        for ref in refs
        if ref.key == candidate or ref.key.endswith(f".{candidate}")
    ]


def _tool_ref(
    tool: Tool,
    refs: list[FunctionRef],
    by_path_name: dict[tuple[Path, str], FunctionRef],
    by_key: dict[str, FunctionRef],
) -> FunctionRef | None:
    existing = tool.metadata.get("source_function_key")
    if isinstance(existing, str) and existing in by_key:
        return by_key[existing]

    names: list[str] = []
    for value in (
        tool.metadata.get("source_function"),
        tool.metadata.get("function"),
        tool.name,
    ):
        if isinstance(value, str) and value and value not in names:
            names.append(value)

    if tool.location is not None:
        path = tool.location.path.resolve()
        local = _unique(
            [
                ref
                for name in names
                if (ref := by_path_name.get((path, name))) is not None
            ]
        )
        if local:
            return local

    import_module = tool.metadata.get("import_module")
    if isinstance(import_module, str) and import_module:
        imported_candidates: list[FunctionRef] = []
        for name in names:
            imported_candidates.extend(
                _suffix_matches(refs, f"{import_module}.{name}")
            )
        imported = _unique(imported_candidates)
        if imported:
            return imported

    source_module = tool.metadata.get("source_module")
    if isinstance(source_module, str) and source_module:
        module_candidates: list[FunctionRef] = []
        for name in names:
            module_candidates.extend(
                _suffix_matches(refs, f"{source_module}.{name}")
            )
        module_ref = _unique(module_candidates)
        if module_ref:
            return module_ref

    return None


def annotate_tool_source_provenance(
    graph: Graph,
    root: Path,
    python_paths: list[Path],
) -> None:
    """Attach canonical source-function provenance where the binding is unique.

    This pass deliberately does not infer from a simple function name across the
    whole repository. It requires same-file evidence, an imported-module binding,
    or an already-resolved source module/key.
    """
    refs = _collect_functions(root, python_paths)
    if not refs:
        return

    by_key = {ref.key: ref for ref in refs}
    by_path_name = {(ref.path, ref.name): ref for ref in refs}

    for tool in graph.all_tools():
        ref = _tool_ref(tool, refs, by_path_name, by_key)
        if ref is None:
            continue

        tool.metadata["source_function_key"] = ref.key
        tool.metadata["source_module"] = ref.module
        tool.metadata["source_function"] = ref.name
        tool.metadata["source_path"] = ref.path.as_posix()
        tool.metadata["source_line"] = ref.line

        import_module = tool.metadata.get("import_module")
        if isinstance(import_module, str) and import_module:
            aliases = tool.metadata.setdefault("import_aliases", [])
            alias = f"{import_module}.{tool.name}"
            if alias not in aliases:
                aliases.append(alias)
