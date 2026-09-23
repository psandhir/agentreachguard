"""Static LangGraph adapter for HorusTrace.

The adapter recognizes common StateGraph construction patterns without importing or
executing the target. It normalizes graph nodes as tools and stores control edges in
agent metadata for projection into the Agent Dependency Graph.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from horustrace.heuristics import infer_capabilities
from horustrace.models import Agent, Graph, InputSource, SourceLocation, Tool

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
    prefixes = ("langgraph", "langgraph_swarm")
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(prefixes):
            return True
        if isinstance(node, ast.Import) and any(alias.name.startswith(prefixes) for alias in node.names):
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


_COMPUTER_READ_ACTIONS = {"take_screenshot", "screenshot"}
_COMPUTER_CONTROL_ONLY_ACTIONS = {"scroll", "move_mouse"}
_COMPUTER_MUTATING_ACTIONS = {
    "click_mouse",
    "double_click",
    "drag_mouse",
    "press_key",
    "type_text",
}
_BROWSER_RECEIVER_MARKERS = {"browser", "page", "locator"}
_BROWSER_READ_METHODS = {"screenshot", "content", "inner_text", "text_content"}
_BROWSER_MUTATING_METHODS = {
    "click",
    "dblclick",
    "fill",
    "press",
    "select_option",
    "set_input_files",
    "type",
    "upload_file",
}
_BROWSER_NETWORK_READ_METHODS = {"download", "goto", "navigate"}


def _computer_control_semantics(
    path: Path | None,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[set[str], dict[str, Any]]:
    """Detect high-confidence custom computer/browser control sinks.

    Detection is intentionally call-shape based. The word "computer" in a function
    or variable name is not enough to establish computer-control authority.
    """
    caps: set[str] = set()
    actions: set[str] = set()
    mutating = False
    read_observed = False
    sink_labels: list[str] = []
    sink_location: SourceLocation | None = None
    mutating_sink_location: SourceLocation | None = None

    for child in ast.walk(node):
        if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
            continue
        called = (_dotted(child.func) or "").lower()
        leaf = child.func.attr.lower()

        if leaf == "computer":
            action_node = _kw(child, "action")
            if action_node is None:
                continue
            literal_action = _literal(action_node)
            action = (
                literal_action.strip().lower()
                if isinstance(literal_action, str)
                else "dynamic"
            )
            actions.add(action)
            caps.add("computer.control")
            label = f"{called}(action={action})"
            sink_labels.append(label)
            current_location = _location(path, child) if path is not None else None
            sink_location = sink_location or current_location

            if action in _COMPUTER_READ_ACTIONS:
                caps.add("data.read")
                read_observed = True
            elif action in _COMPUTER_CONTROL_ONLY_ACTIONS:
                pass
            elif action in _COMPUTER_MUTATING_ACTIONS or action == "dynamic":
                # Dynamic dispatch can select a mutating operation at runtime, while
                # unknown literal actions remain control-only until their semantics
                # are explicitly recognized.
                mutating = True
                caps.add("external.write")
                mutating_sink_location = mutating_sink_location or current_location
            continue

        receiver = (_dotted(child.func.value) or _call_name(child.func.value) or "").lower()
        receiver_tokens = set(receiver.replace("-", "_").replace(".", "_").split("_"))
        if not (receiver_tokens & _BROWSER_RECEIVER_MARKERS):
            continue

        if leaf in _BROWSER_READ_METHODS:
            caps.update({"computer.control", "data.read"})
            actions.add(leaf)
            read_observed = True
        elif leaf in _BROWSER_MUTATING_METHODS:
            caps.update({"computer.control", "external.write"})
            actions.add(leaf)
            mutating = True
        elif leaf in _BROWSER_NETWORK_READ_METHODS:
            caps.update({"computer.control", "data.read", "network.external"})
            actions.add(leaf)
            read_observed = True
        else:
            continue

        label = called
        sink_labels.append(label)
        current_location = _location(path, child) if path is not None else None
        sink_location = sink_location or current_location
        if mutating and mutating_sink_location is None:
            mutating_sink_location = current_location

    metadata: dict[str, Any] = {}
    if "computer.control" in caps:
        metadata = {
            "computer_control_custom": True,
            "computer_control_actions": sorted(actions),
            "computer_control_mutating": mutating,
            "computer_control_readonly": read_observed and not mutating,
            "computer_control_sinks": sink_labels,
            "computer_control_sink": sink_labels[0] if sink_labels else None,
            "computer_control_sink_location": mutating_sink_location or sink_location,
            "computer_control_evidence": "call_shape",
        }
    return caps, metadata


def _function_capabilities(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    caps = _name_capabilities(node.name)
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called = (_dotted(child.func) or _call_name(child.func) or "").lower()
        leaf = (_call_name(child.func) or "").lower()
        if (
            called in {"exec", "eval", "compile", "builtins.exec", "builtins.eval", "builtins.compile"}
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
    computer_caps, _ = _computer_control_semantics(None, node)
    caps.update(computer_caps)
    return caps


def _function_has_human_approval_gate(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Return True only for an explicit human interrupt plus approval semantics."""
    has_interrupt = False
    has_approval_semantics = False
    approval_markers = {"approved", "approve", "accept", "accepted", "confirm", "confirmed"}

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            called = (_dotted(child.func) or _call_name(child.func) or "").lower()
            if called == "interrupt" or called.endswith(".interrupt"):
                has_interrupt = True
        if (
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and child.value.strip().lower() in approval_markers
        ):
            has_approval_semantics = True

    return has_interrupt and has_approval_semantics


def _string_ref(node: ast.AST | None) -> str | None:
    literal = _literal(node)
    if isinstance(literal, str):
        return literal
    return _call_name(node)


def _target_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    return _dotted(node)


def _route_target(node: ast.AST | None) -> str | None:
    value = _string_ref(node)
    if value == "END":
        return "__end__"
    if value == "START":
        return "__start__"
    return value


def _path_map_targets(node: ast.AST | None) -> list[str]:
    if isinstance(node, ast.Dict):
        values = node.values
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = node.elts
    else:
        return []
    targets = [
        target
        for value in values
        if (target := _route_target(value)) is not None
    ]
    return list(dict.fromkeys(targets))


def _return_targets(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[str]:
    targets: list[str] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        values = (
            [node.value.body, node.value.orelse]
            if isinstance(node.value, ast.IfExp)
            else [node.value]
        )
        for value in values:
            target = _route_target(value)
            if target:
                targets.append(target)
    return list(dict.fromkeys(targets))


def _resolved_tool_elements(expr: ast.AST | None, sequences: dict[str, list[ast.AST]]) -> list[ast.AST]:
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return list(expr.elts)
    if isinstance(expr, ast.Name):
        return list(sequences.get(expr.id, []))
    return []


def _factory_agent(
    path: Path,
    alias: str,
    call: ast.Call,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    sequences: dict[str, list[ast.AST]],
) -> Agent:
    call_name = _call_name(call.func) or "langgraph_factory"
    agent = Agent(
        name=alias,
        location=_location(path, call),
        metadata={
            "framework": "langgraph",
            "agent_type": call_name,
            "workflow": "LangGraph",
            "control_edges": [],
            "memory": [],
            "factory_agent": True,
            "instance_key": (
                f"{path.resolve()}:{getattr(call, 'lineno', 1)}:{alias}"
            ),
        },
    )
    tools_expr = _kw(call, "tools")
    if tools_expr is None and len(call.args) > 1:
        tools_expr = call.args[1]
    elements = _resolved_tool_elements(tools_expr, sequences)
    for element in elements:
        tool_name = _call_name(element)
        if not tool_name:
            continue
        caps = _name_capabilities(tool_name)
        tool_metadata: dict[str, Any] = {
            "framework": "langgraph",
            "factory": call_name,
        }
        if tool_name in functions:
            function = functions[tool_name]
            caps.update(_function_capabilities(function))
            _, computer_metadata = _computer_control_semantics(path, function)
            tool_metadata.update(computer_metadata)
        agent.tools.append(
            Tool(
                name=tool_name,
                kind="langgraph_tool",
                capabilities=caps,
                location=_location(path, element),
                metadata=tool_metadata,
            )
        )
    if tools_expr is not None and not elements:
        agent.metadata["dynamic_tools"] = True
    checkpointer = _call_name(_kw(call, "checkpointer"))
    if checkpointer:
        agent.metadata["checkpointer_ref"] = checkpointer
    return agent


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
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    sequences: dict[str, list[ast.AST]] = {}
    graph_aliases: dict[str, ast.Call] = {}
    memory_aliases: dict[str, dict[str, Any]] = {}
    factory_agents: list[Agent] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        aliases = [name for target in targets if (name := _target_name(target))]
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            for alias in aliases:
                sequences[alias] = list(value.elts)
            continue
        if not isinstance(value, ast.Call) or not aliases:
            continue
        call_name = _call_name(value.func) or ""
        alias = aliases[0]
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
        if call_name in {
            "create_react_agent",
            "create_supervisor",
            "create_swarm",
            "create_handoff_back_messages",
        }:
            factory_agents.append(_factory_agent(path, alias, value, functions, sequences))

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
                "instance_key": (
                    f"{path.resolve()}:{getattr(constructor, 'lineno', 1)}:{graph_alias}"
                ),
            },
        )
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
                if (
                    node_name is None
                    and isinstance(call.args[0], ast.Call)
                    and _call_name(call.args[0].func) == "ToolNode"
                ):
                    node_name = "tools"
                function_node = call.args[1] if len(call.args) > 1 else _kw(call, "action")
                function_name = _call_name(function_node)
                if not node_name:
                    unresolved_dynamic_edge = True
                    continue
                caps = _name_capabilities(node_name)
                computer_metadata: dict[str, Any] = {}
                if function_name and function_name in functions:
                    function = functions[function_name]
                    caps.update(_function_capabilities(function))
                    _, computer_metadata = _computer_control_semantics(path, function)
                approval_control = bool(
                    function_name
                    and function_name in functions
                    and _function_has_human_approval_gate(functions[function_name])
                )
                tool_metadata = {
                    "framework": "langgraph",
                    "function": function_name,
                    "graph": graph_alias,
                    "approval_control": approval_control,
                    "approval_mechanism": (
                        "langgraph_human_interrupt" if approval_control else None
                    ),
                }
                tool_metadata.update(computer_metadata)
                tool = Tool(
                    name=node_name,
                    kind="langgraph_node",
                    capabilities=caps,
                    guardrails=approval_control,
                    location=_location(path, call),
                    metadata=tool_metadata,
                )
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
                router = _call_name(call.args[1]) if len(call.args) > 1 else None
                path_map_node = (
                    call.args[2]
                    if len(call.args) > 2
                    else _kw(call, "path_map")
                )
                targets = _path_map_targets(path_map_node)
                if not targets and router and router in functions:
                    targets.extend(_return_targets(functions[router]))
                elif not targets and router == "tools_condition":
                    targets.extend(["tools", "__end__"])
                if source and targets:
                    for target in targets:
                        agent.metadata["control_edges"].append((source, target))
                else:
                    # Keep uncertainty only when the finite router target set
                    # cannot be established from explicit path maps or returns.
                    unresolved_dynamic_edge = True

            elif method == "compile":
                checkpointer = _call_name(_kw(call, "checkpointer"))
                if checkpointer and checkpointer in memory_aliases:
                    agent.metadata["memory"].append(memory_aliases[checkpointer])

        if unresolved_dynamic_edge:
            agent.metadata["dynamic_control_flow"] = True
        agent.metadata["control_edges"] = list(dict.fromkeys(agent.metadata["control_edges"]))

        tools_by_name = {tool.name: tool for tool in agent.tools}
        for source, target in agent.metadata["control_edges"]:
            gate = tools_by_name.get(str(source))
            protected = tools_by_name.get(str(target))
            if not gate or not protected or not gate.metadata.get("approval_control"):
                continue
            protected.approval = True
            protected.guardrails = True
            protected.metadata["approval_gated_by"] = gate.name
            protected.metadata["approval_mechanism"] = "langgraph_human_interrupt"
            protected.metadata["approval_scope"] = "execution_gate"
            protected.metadata["approval_mandatory"] = True

        graph.agents.append(agent)

    for agent in factory_agents:
        ref = agent.metadata.pop("checkpointer_ref", None)
        if ref and ref in memory_aliases:
            agent.metadata["memory"].append(memory_aliases[ref])
        graph.agents.append(agent)

    return graph
