"""Bounded static source-to-sink analysis for HorusTrace v0.4.

This module deliberately implements a conservative supported subset rather than
claiming arbitrary-Python taint analysis. It follows direct assignments, common
expressions, resolved local/imported helper calls, and a small set of explicit
source/sink APIs. Unresolved runtime semantics are not treated as proof of safety.
"""
from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from horustrace.coverage import add_diagnostic
from horustrace.limits import (
    MAX_FLOW_PATHS,
    MAX_FLOW_STEPS,
    MAX_FLOW_SUMMARY_ITERATIONS,
)
from horustrace.models import (
    Confidence,
    FlowPath,
    FlowStep,
    Graph,
    ScanDiagnostic,
    SourceLocation,
)


@dataclass(frozen=True, slots=True)
class _Source:
    source_id: str
    kind: str
    label: str
    location: SourceLocation


@dataclass(frozen=True, slots=True)
class _Unresolved:
    called: str
    location: SourceLocation


@dataclass(frozen=True, slots=True)
class _Value:
    params: frozenset[str] = frozenset()
    sources: tuple[_Source, ...] = ()
    unresolved: tuple[_Unresolved, ...] = ()

    @classmethod
    def combine(cls, values: Iterable[_Value]) -> _Value:
        params: set[str] = set()
        sources: dict[str, _Source] = {}
        unresolved: dict[tuple[str, str, int], _Unresolved] = {}
        for value in values:
            params.update(value.params)
            for source in value.sources:
                sources[source.source_id] = source
            for item in value.unresolved:
                key = (item.called, item.location.path.as_posix(), item.location.line)
                unresolved[key] = item
        return cls(
            frozenset(params),
            tuple(sources[key] for key in sorted(sources)),
            tuple(unresolved[key] for key in sorted(unresolved)),
        )


@dataclass(frozen=True, slots=True)
class _Sink:
    kind: str
    label: str
    location: SourceLocation
    value: _Value
    call_chain: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Summary:
    returns: _Value = _Value()
    sinks: tuple[_Sink, ...] = ()


@dataclass(slots=True)
class _Function:
    key: str
    module: str
    name: str
    path: Path
    node: ast.FunctionDef | ast.AsyncFunctionDef
    imports: dict[str, str] = field(default_factory=dict)

    @property
    def params(self) -> list[str]:
        args = [*self.node.args.posonlyargs, *self.node.args.args, *self.node.args.kwonlyargs]
        names = [arg.arg for arg in args]
        if self.node.args.vararg:
            names.append(self.node.args.vararg.arg)
        if self.node.args.kwarg:
            names.append(self.node.args.kwarg.arg)
        return names


_PASSTHROUGH_METHODS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "casefold", "replace", "format",
    "join", "split", "rsplit", "encode", "decode", "removeprefix", "removesuffix",
}
_SAFE_TRANSFORM_CALLS = {
    "str", "repr", "bytes", "list", "tuple", "set", "dict",
    "json.dumps", "json.loads", "urllib.parse.quote", "urllib.parse.urlencode",
}
_SECRET_ENV_MARKERS = {
    "secret", "token", "password", "api_key", "apikey", "private_key", "credential",
}


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


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


def _collect_functions(root: Path, python_paths: list[Path]) -> dict[str, _Function]:
    functions: dict[str, _Function] = {}
    for path in sorted(python_paths):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        module = _module_name(path, root)
        imports = _imports(tree)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            key = f"{module}.{node.name}" if module else node.name
            functions[key] = _Function(key, module, node.name, path, node, imports)
    return functions


def _resolve_callee(
    info: _Function,
    called: str,
    functions: dict[str, _Function],
    unique_simple: dict[str, str],
) -> str | None:
    if "." not in called:
        imported = info.imports.get(called)
        if imported in functions:
            return imported
        local = f"{info.module}.{called}" if info.module else called
        if local in functions:
            return local
        return unique_simple.get(called)

    first, rest = called.split(".", 1)
    imported_module = info.imports.get(first)
    if imported_module:
        candidate = f"{imported_module}.{rest}"
        if candidate in functions:
            return candidate
    if called in functions:
        return called
    return None


def _source_kind(called: str) -> tuple[str, str] | None:
    lower = called.lower()
    leaf = lower.rsplit(".", 1)[-1]
    if lower == "input" or leaf == "input":
        return "user_input", "user-controlled input"
    if (
        lower.startswith(("requests.get", "httpx.get"))
        or lower.endswith(".session.get")
        or "urllib.request.urlopen" in lower
        or ("aiohttp" in lower and leaf == "get")
    ):
        return "external_http_response", called
    if leaf in {
        "google_search", "web_search", "search_web", "load_web_page", "url_context",
        "retrieve_web", "fetch_web_page",
    }:
        return "web_retrieval", called
    if "mcp" in lower and leaf in {"call_tool", "invoke_tool"}:
        return "mcp_response", called
    if (
        "secretmanager" in lower
        or "vault" in lower
        or leaf in {"get_secret", "read_secret", "fetch_secret", "access_secret_version"}
    ):
        return "secret_value", called
    return None


def _sink_kind(called: str) -> tuple[str, str] | None:
    lower = called.lower()
    leaf = lower.rsplit(".", 1)[-1]
    if (
        lower in {"exec", "eval", "compile", "os.system", "os.popen"}
        or lower.startswith("subprocess.")
        or "create_subprocess_" in lower
        or leaf in {"run_command", "execute_bash", "shell_command"}
    ):
        return "process_execute", called
    if (
        lower.startswith((
            "requests.post", "requests.put", "requests.patch", "requests.delete",
            "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
        ))
        or leaf in {"send_email", "send_message", "upload_file", "publish_message"}
    ):
        return "external_send", called
    memory_marked = "memory" in lower or "checkpoint" in lower
    if memory_marked and leaf in {"save", "store", "add", "put", "update", "write", "append", "set"}:
        return "memory_write", called
    if leaf in {"save_memory", "store_memory", "add_memory", "update_memory", "put_memory"}:
        return "memory_write", called
    return None


def _sink_value(called: str, call: ast.Call, evaluator) -> _Value:
    kind = _sink_kind(called)
    if kind and kind[0] == "external_send":
        values = [evaluator(arg) for arg in call.args[1:]]
        values.extend(
            evaluator(keyword.value)
            for keyword in call.keywords
            if keyword.arg in {"data", "json", "content", "body", "files"}
        )
        if values:
            return _Value.combine(values)
    values = [evaluator(arg) for arg in call.args]
    values.extend(evaluator(keyword.value) for keyword in call.keywords)
    return _Value.combine(values)


def _instantiate(value: _Value, parameters: dict[str, _Value]) -> _Value:
    values = [
        _Value(sources=value.sources, unresolved=value.unresolved),
        *(parameters.get(param, _Value(params=frozenset({param}))) for param in value.params),
    ]
    return _Value.combine(values)


class _FunctionAnalyzer:
    def __init__(
        self,
        info: _Function,
        functions: dict[str, _Function],
        summaries: dict[str, _Summary],
        unique_simple: dict[str, str],
    ):
        self.info = info
        self.functions = functions
        self.summaries = summaries
        self.unique_simple = unique_simple
        self.sinks: list[_Sink] = []
        self.return_values: list[_Value] = []

    def run(self) -> _Summary:
        env = {name: _Value(params=frozenset({name})) for name in self.info.params}
        self._statements(self.info.node.body, env)
        deduplicated: dict[tuple, _Sink] = {}
        for item in self.sinks:
            key = (
                item.kind, item.label, item.location.path.as_posix(), item.location.line,
                tuple(sorted(item.value.params)),
                tuple(source.source_id for source in item.value.sources),
                item.call_chain,
            )
            deduplicated[key] = item
        sinks = tuple(sorted(deduplicated.values(), key=lambda item: (
            item.location.path.as_posix(), item.location.line, item.kind, item.label,
            item.call_chain,
        )))
        return _Summary(_Value.combine(self.return_values), sinks)

    def _statements(self, statements: list[ast.stmt], env: dict[str, _Value]) -> None:
        for statement in statements:
            if isinstance(statement, ast.Assign):
                value = self._expr(statement.value, env)
                for target in statement.targets:
                    self._assign(target, value, env)
            elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
                self._assign(statement.target, self._expr(statement.value, env), env)
            elif isinstance(statement, ast.AugAssign):
                value = _Value.combine((self._expr(statement.target, env), self._expr(statement.value, env)))
                self._assign(statement.target, value, env)
            elif isinstance(statement, ast.Expr):
                self._expr(statement.value, env)
            elif isinstance(statement, ast.Return):
                self.return_values.append(self._expr(statement.value, env) if statement.value else _Value())
            elif isinstance(statement, ast.If):
                self._expr(statement.test, env)
                left = dict(env)
                right = dict(env)
                self._statements(statement.body, left)
                self._statements(statement.orelse, right)
                self._merge_env(env, left, right)
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                loop_env = dict(env)
                iterable = self._expr(statement.iter, env)
                self._assign(statement.target, iterable, loop_env)
                self._statements(statement.body, loop_env)
                self._statements(statement.orelse, loop_env)
                self._merge_env(env, env, loop_env)
            elif isinstance(statement, ast.While):
                self._expr(statement.test, env)
                loop_env = dict(env)
                self._statements(statement.body, loop_env)
                self._statements(statement.orelse, loop_env)
                self._merge_env(env, env, loop_env)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                scoped = dict(env)
                for item in statement.items:
                    value = self._expr(item.context_expr, env)
                    if item.optional_vars:
                        self._assign(item.optional_vars, value, scoped)
                self._statements(statement.body, scoped)
                self._merge_env(env, env, scoped)
            elif isinstance(statement, ast.Try):
                branches: list[dict[str, _Value]] = []
                normal = dict(env)
                self._statements(statement.body, normal)
                branches.append(normal)
                for handler in statement.handlers:
                    branch = dict(env)
                    self._statements(handler.body, branch)
                    branches.append(branch)
                final = dict(env)
                self._statements(statement.finalbody, final)
                branches.append(final)
                self._merge_env(env, *branches)
                self._statements(statement.orelse, env)

    def _merge_env(self, target: dict[str, _Value], *branches: dict[str, _Value]) -> None:
        keys = set().union(*(branch.keys() for branch in branches))
        for key in keys:
            target[key] = _Value.combine(branch.get(key, _Value()) for branch in branches)

    def _assign(self, target: ast.AST, value: _Value, env: dict[str, _Value]) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign(element, value, env)

    def _expr(self, node: ast.AST | None, env: dict[str, _Value]) -> _Value:
        if node is None:
            return _Value()
        if isinstance(node, ast.Name):
            return env.get(node.id, _Value())
        if isinstance(node, ast.Constant):
            return _Value()
        if isinstance(node, ast.Attribute):
            return self._expr(node.value, env)
        if isinstance(node, ast.Subscript):
            return _Value.combine((self._expr(node.value, env), self._expr(node.slice, env)))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return _Value.combine(self._expr(item, env) for item in node.elts)
        if isinstance(node, ast.Dict):
            return _Value.combine(
                [self._expr(item, env) for item in node.keys if item is not None]
                + [self._expr(item, env) for item in node.values]
            )
        if isinstance(node, ast.JoinedStr):
            return _Value.combine(self._expr(value, env) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._expr(node.value, env)
        if isinstance(node, ast.BinOp):
            return _Value.combine((self._expr(node.left, env), self._expr(node.right, env)))
        if isinstance(node, ast.BoolOp):
            return _Value.combine(self._expr(value, env) for value in node.values)
        if isinstance(node, ast.IfExp):
            return _Value.combine((
                self._expr(node.test, env), self._expr(node.body, env), self._expr(node.orelse, env),
            ))
        if isinstance(node, ast.UnaryOp):
            return self._expr(node.operand, env)
        if isinstance(node, ast.Compare):
            return _Value.combine(
                [self._expr(node.left, env), *(self._expr(item, env) for item in node.comparators)]
            )
        if not isinstance(node, ast.Call):
            children = [self._expr(child, env) for child in ast.iter_child_nodes(node)]
            return _Value.combine(children)

        called = _dotted(node.func) or (node.func.id if isinstance(node.func, ast.Name) else "")
        lower_called = called.lower()
        source = _source_kind(called)
        if source is None and lower_called in {"os.getenv", "os.environ.get"} and node.args:
            key = node.args[0]
            if (
                isinstance(key, ast.Constant)
                and isinstance(key.value, str)
                and any(marker in key.value.lower() for marker in _SECRET_ENV_MARKERS)
            ):
                source = ("secret_value", called)
        if source:
            location = _location(self.info.path, node)
            relative = self.info.path.as_posix()
            token = f"{relative}:{location.line}:{source[0]}:{source[1]}"
            source_id = "source-v1:" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:20]
            return _Value(sources=(_Source(source_id, source[0], source[1], location),))

        sink = _sink_kind(called)
        if sink:
            value = _sink_value(called, node, lambda item: self._expr(item, env))
            self.sinks.append(
                _Sink(
                    sink[0], sink[1], _location(self.info.path, node), value, (self.info.key,),
                )
            )
            return _Value()

        callee_key = _resolve_callee(self.info, called, self.functions, self.unique_simple)
        if callee_key and callee_key in self.summaries:
            summary = self.summaries[callee_key]
            callee = self.functions[callee_key]
            positional = [self._expr(arg, env) for arg in node.args]
            keyword_values = {
                keyword.arg: self._expr(keyword.value, env)
                for keyword in node.keywords
                if keyword.arg is not None
            }
            parameters: dict[str, _Value] = {}
            for index, name in enumerate(callee.params):
                if index < len(positional):
                    parameters[name] = positional[index]
                elif name in keyword_values:
                    parameters[name] = keyword_values[name]
                else:
                    parameters[name] = _Value()
            for child_sink in summary.sinks:
                self.sinks.append(
                    _Sink(
                        child_sink.kind,
                        child_sink.label,
                        child_sink.location,
                        _instantiate(child_sink.value, parameters),
                        (self.info.key, *child_sink.call_chain),
                    )
                )
            return _instantiate(summary.returns, parameters)

        leaf = called.rsplit(".", 1)[-1].lower() if called else ""
        if leaf in _PASSTHROUGH_METHODS and isinstance(node.func, ast.Attribute):
            return _Value.combine(
                [self._expr(node.func.value, env), *(self._expr(arg, env) for arg in node.args)]
            )

        # Preserve taint conservatively across an unresolved call, but mark the
        # dependency as incomplete rather than promoting it to supported flow.
        # This avoids silently dropping attacker-controlled values while also
        # avoiding a false claim that arbitrary helper semantics were proven.
        values = [self._expr(arg, env) for arg in node.args]
        values.extend(self._expr(keyword.value, env) for keyword in node.keywords)
        if isinstance(node.func, ast.Attribute):
            values.append(self._expr(node.func.value, env))
        combined = _Value.combine(values)
        if combined.params or combined.sources or combined.unresolved:
            if called in _SAFE_TRANSFORM_CALLS:
                return combined
            unresolved = _Unresolved(called or "<dynamic-call>", _location(self.info.path, node))
            return _Value.combine((combined, _Value(unresolved=(unresolved,))))
        return _Value()


def _simple_name_index(functions: dict[str, _Function]) -> dict[str, str]:
    values: dict[str, list[str]] = {}
    for key, info in functions.items():
        values.setdefault(info.name, []).append(key)
    return {name: keys[0] for name, keys in values.items() if len(keys) == 1}


def _build_summaries(functions: dict[str, _Function]) -> dict[str, _Summary]:
    summaries = {key: _Summary() for key in functions}
    unique_simple = _simple_name_index(functions)
    for _ in range(MAX_FLOW_SUMMARY_ITERATIONS):
        changed = False
        next_summaries: dict[str, _Summary] = {}
        for key in sorted(functions):
            summary = _FunctionAnalyzer(
                functions[key], functions, summaries, unique_simple,
            ).run()
            next_summaries[key] = summary
            if summary != summaries[key]:
                changed = True
        summaries = next_summaries
        if not changed:
            break
    return summaries


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _agent_for_chain(graph: Graph, functions: dict[str, _Function], chain: tuple[str, ...]) -> str | None:
    """Bind a flow to an agent only when the static tool relationship is unambiguous.

    Framework adapters often declare an imported tool in one file while the
    implementation lives in another. Requiring the declaration and implementation
    paths to match therefore loses valid attribution. Prefer same-file evidence,
    but allow a cross-file name/function binding when it identifies exactly one
    normalized agent.
    """
    same_file: list[str] = []
    cross_file: list[str] = []

    for function_key in chain:
        info = functions.get(function_key)
        if not info:
            continue
        for agent in graph.agents:
            for tool in agent.tools:
                function_name = tool.metadata.get("function")
                if tool.name != info.name and function_name != info.name:
                    continue
                if tool.location is None or tool.location.path.resolve() == info.path.resolve():
                    same_file.append(agent.name)
                else:
                    cross_file.append(agent.name)

    exact = list(dict.fromkeys(same_file))
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        return None

    inferred = list(dict.fromkeys(cross_file))
    if len(inferred) == 1:
        return inferred[0]
    if not inferred and len(graph.agents) == 1:
        return graph.agents[0].name
    return None


def _flow_id(root: Path, source: _Source, sink: _Sink, agent: str | None) -> str:
    payload = "\0".join((
        source.kind,
        source.label,
        _relative(source.location.path, root),
        str(source.location.line),
        sink.kind,
        sink.label,
        _relative(sink.location.path, root),
        str(sink.location.line),
        agent or "",
        *sink.call_chain,
    ))
    return "flow-v1:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def analyze_repository_flows(root: Path, python_paths: list[Path], graph: Graph) -> list[FlowPath]:
    """Return deterministic supported static source-to-sink paths.

    Only explicit supported sources and sinks are considered. A returned path means
    HorusTrace established a static value dependency through supported constructs;
    it is still not proof that the path is exploitable at runtime.
    """
    root = root.resolve()
    functions = _collect_functions(root, python_paths)
    if not functions:
        return []
    summaries = _build_summaries(functions)
    result: list[FlowPath] = []
    seen: set[str] = set()

    for function_key in sorted(summaries):
        summary = summaries[function_key]
        for sink in summary.sinks:
            if not sink.value.sources:
                continue
            agent = _agent_for_chain(graph, functions, sink.call_chain)
            for source in sink.value.sources:
                flow_id = _flow_id(root, source, sink, agent)
                if flow_id in seen:
                    continue
                seen.add(flow_id)
                chain = list(dict.fromkeys(sink.call_chain))
                steps: list[FlowStep] = [
                    FlowStep(source.kind, source.label, source.location),
                ]
                for key in chain:
                    info = functions.get(key)
                    if not info:
                        continue
                    steps.append(
                        FlowStep(
                            "function",
                            info.key,
                            _location(info.path, info.node),
                        )
                    )
                steps.append(FlowStep(sink.kind, sink.label, sink.location))
                if len(steps) > MAX_FLOW_STEPS:
                    steps = [*steps[: MAX_FLOW_STEPS - 1], steps[-1]]
                unresolved_items = [
                    {
                        "call": item.called,
                        "path": _relative(item.location.path, root),
                        "line": item.location.line,
                    }
                    for item in sink.value.unresolved
                ]
                basis = "static_dataflow_partial" if unresolved_items else "static_dataflow"
                confidence = Confidence.POTENTIAL if unresolved_items else Confidence.SUPPORTED
                result.append(
                    FlowPath(
                        flow_id=flow_id,
                        source_kind=source.kind,
                        sink_kind=sink.kind,
                        source_label=source.label,
                        sink_label=sink.label,
                        steps=steps,
                        agent=agent,
                        basis=basis,
                        confidence=confidence,
                        metadata={
                            "call_chain": chain,
                            "unresolved_calls": unresolved_items,
                        },
                    )
                )
                for item in sink.value.unresolved:
                    add_diagnostic(
                        graph.coverage,
                        ScanDiagnostic(
                            "unresolved_dataflow",
                            "A tainted value crosses a call whose return/data-flow semantics could not be resolved.",
                            item.location,
                        ),
                    )
                if len(result) >= MAX_FLOW_PATHS:
                    return sorted(result, key=lambda item: item.flow_id)
    return sorted(result, key=lambda item: item.flow_id)
