"""Static LangGraph adapter for AgentReachGuard v0.4.

The adapter recognizes common StateGraph construction patterns without importing or
executing the target. It normalizes graph nodes as tools and stores control edges in
agent metadata for projection into the Agent Dependency Graph.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from agentreachguard.heuristics import infer_capabilities
from agentreachguard.models import Agent, Graph, InputSource, SourceLocation, Tool

_GRAPH_TYPES = {"StateGraph", "MessageGraph"}
_RETRIEVAL_MARKERS = ("search", "retrieve", "browser", "web", "fetch", "document")
_MEMORY_TYPES = {
    "MemorySaver": (False, "memory"),
    "InMemorySaver": (False, "memory"),
    "SqliteSaver": (True, "sqlite"),
    "AsyncSqliteSaver": (True, "sqlite"),
    "PostgresSaver": (True, "postgres"),
    "AsyncPostgresSaver": (True, "postgres"),
}


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        line=getattr(node, "lineno", 1) or 1,
        column=(getattr(node, "col_offset", 0) or 0) + 1,
    )


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _dotted(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError):
        return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in call.keywords if item.arg == name), None)


def _uses_langgraph(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("langgraph"):
            return True
        if isinstance(node, ast.Import) and any(alias.name.startswith("langgraph") for alias in node.names):
            return True
    return False


def is_langgraph_file(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return False
    return _uses_langgraph(tree)


def _name_capabilities(name: str) -> set[str]:
    caps = set(infer_capabilities(name))
    tokens = set(name.lower().replace("-", "_").replace(".", "_").split("_"))
    if "process.execute" in caps and not (
        tokens & {"shell", "bash", "powershell", "command", "terminal", "exec"}
    ):
        caps.discard("process.execute")
    return caps


def _function_capabilities(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    caps = _name_capabilities(node.name)
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()
        if (
            leaf in {"exec", "eval", "compile"}
            or called in {"os.system", "os.popen"}
            or called.startswith("subprocess.")
            or "create_subprocess_" in called
        ):
            caps.add("process.execute")
        if called.startswith(("requests.", "httpx.")) or "urllib" in called or "aiohttp" in called:
            caps.add("network.external")
            if leaf in {"post", "put", "patch", "delete"}:
                caps.add("external.write")
        if leaf in {"write", "update", "save", "insert", "create", "put"}:
            caps.add("data.write")
        if leaf in {"read", "get", "search", "retrieve", "fetch", "query"}:
            caps.add("data.read")
        if "secretmanager" in called or "vault" in called or leaf in {"get_secret", "access_secret_version"}:
            caps.add("secrets.read")
    return caps


def _string_ref(node: ast.AST | None) -> str | None:
    literal = _literal(node)
    if isinstance(literal, str):
        return literal
    return _call_name(node)


def scan_python_file(path: Path) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return graph
    if not _uses_langgraph(tree):
        return graph

    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    graph_aliases: dict[str, ast.Call] = {}
    memory_aliases: dict[str, dict[str, Any]] = {}

    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        alias = next((target.id for target in targets if isinstance(target, ast.Name)), None)
        if not alias:
            continue
        call_name = _call_name(value.func) or ""
        if call_name in _GRAPH_TYPES:
            graph_aliases[alias] = value
        if call_name in _MEMORY_TYPES:
            persistent, backend = _MEMORY_TYPES[call_name]
            memory_aliases[alias] = {
                "name": alias,
                "persistent": persistent,
                "backend": backend,
                "writable": True,
            }

    for graph_alias, constructor in graph_aliases.items():
        agent = Agent(
            name=graph_alias,
            location=_location(path, constructor),
            metadata={
                "framework": "langgraph",
                "agent_type": _call_name(constructor.func) or "StateGraph",
                "workflow": "LangGraph",
                "control_edges": [],
                "memory": [],
            },
        )
        node_tools: dict[str, Tool] = {}
        unresolved_dynamic_edge = False

        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if not isinstance(call.func, ast.Attribute):
                continue
            receiver = _dotted(call.func.value) or _call_name(call.func.value)
            if receiver != graph_alias:
                continue
            method = call.func.attr

            if method == "add_node" and call.args:
                node_name = _string_ref(call.args[0])
                function_node = call.args[1] if len(call.args) > 1 else _kw(call, "action")
                function_name = _call_name(function_node)
                if not node_name:
                    continue
                caps = _name_capabilities(node_name)
                if function_name and function_name in functions:
                    caps.update(_function_capabilities(functions[function_name]))
                tool = Tool(
                    name=node_name,
                    kind="langgraph_node",
                    capabilities=caps,
                    location=_location(path, call),
                    metadata={
                        "framework": "langgraph",
                        "function": function_name,
                        "graph": graph_alias,
                    },
                )
                node_tools[node_name] = tool
                agent.tools.append(tool)
                if any(marker in node_name.lower() for marker in _RETRIEVAL_MARKERS):
                    agent.inputs.append(
                        InputSource(
                            name=f"{node_name}:external-content",
                            trust="untrusted",
                            kind="retrieval",
                            location=tool.location,
                            metadata={"inferred": True},
                        )
                    )

            elif method == "add_edge" and len(call.args) >= 2:
                source = _string_ref(call.args[0])
                target = _string_ref(call.args[1])
                if source and target:
                    agent.metadata["control_edges"].append((source, target))
                else:
                    unresolved_dynamic_edge = True

            elif method == "add_conditional_edges" and call.args:
                source = _string_ref(call.args[0])
                path_map = _literal(call.args[2]) if len(call.args) > 2 else _literal(_kw(call, "path_map"))
                if source and isinstance(path_map, dict):
                    for target in path_map.values():
                        if isinstance(target, str):
                            agent.metadata["control_edges"].append((source, target))
                else:
                    unresolved_dynamic_edge = True

            elif method == "compile":
                checkpointer = _call_name(_kw(call, "checkpointer"))
                if checkpointer and checkpointer in memory_aliases:
                    agent.metadata["memory"].append(memory_aliases[checkpointer])

        if unresolved_dynamic_edge:
            agent.metadata["dynamic_control_flow"] = True
        # Deduplicate while preserving graph construction order.
        agent.metadata["control_edges"] = list(dict.fromkeys(agent.metadata["control_edges"]))
        graph.agents.append(agent)

    return graph
