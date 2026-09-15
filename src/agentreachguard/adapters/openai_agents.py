from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agentreachguard.heuristics import infer_capabilities
from agentreachguard.models import (
    Agent,
    Graph,
    InputSource,
    MCPServer,
    NetworkDestination,
    SourceLocation,
    Tool,
)

MCP_TYPES = {
    "MCPServerStdio": "stdio",
    "MCPServerSse": "sse",
    "MCPServerStreamableHttp": "streamable-http",
}


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _approval_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.lower()
        if lowered == "always":
            return True
        if lowered == "never":
            return False
    if isinstance(value, dict):
        values = list(value.values())
        if "always" in values or "always" in value or True in values:
            return True
        if values and all(v in {"never", False} for v in values):
            return False
    return None


def _location(path: Path, node: ast.AST) -> SourceLocation:
    return SourceLocation(path=path, line=getattr(node, "lineno", 1), column=getattr(node, "col_offset", 0) + 1)


def _tool_from_call(path: Path, node: ast.Call, alias: str | None = None) -> Tool | None:
    name = _call_name(node.func)
    if not name:
        return None

    if name == "ShellTool":
        approval = _approval_value(_literal(_kw(node, "needs_approval")))
        if approval is None:
            approval = _kw(node, "on_approval") is not None
        return Tool(
            name=alias or "ShellTool",
            kind="shell",
            capabilities={"process.execute", "data.read", "data.write", "network.external"},
            approval=approval,
            location=_location(path, node),
            metadata={"implicit_network": True},
        )

    if name == "ApplyPatchTool":
        approval = _approval_value(_literal(_kw(node, "needs_approval")))
        if approval is None:
            approval = _kw(node, "on_approval") is not None
        return Tool(
            name=alias or "ApplyPatchTool",
            kind="apply_patch",
            capabilities={"data.write"},
            approval=approval,
            location=_location(path, node),
        )

    if name == "HostedMCPTool":
        config = _literal(_kw(node, "tool_config")) or {}
        server_label = str(config.get("server_label") or alias or "hosted-mcp")
        approval = _approval_value(config.get("require_approval"))
        tool = Tool(
            name=server_label,
            kind="hosted_mcp",
            capabilities={"mcp.remote", "network.external"},
            approval=approval,
            guardrails=_kw(node, "on_approval_request") is not None,
            location=_location(path, node),
            metadata={
                "server_url": config.get("server_url"),
                "connector_id": config.get("connector_id"),
                "allowed_tools": config.get("allowed_tools"),
            },
        )
        if config.get("server_url"):
            tool.destinations.append(
                NetworkDestination(
                    target=str(config["server_url"]),
                    restricted=True,
                    location=tool.location,
                )
            )
        return tool

    return None


def _mcp_from_call(path: Path, node: ast.Call, alias: str) -> MCPServer | None:
    call_name = _call_name(node.func)
    if call_name not in MCP_TYPES:
        return None

    params = _literal(_kw(node, "params")) or {}
    url = params.get("url") if isinstance(params, dict) else None
    command = params.get("command") if isinstance(params, dict) else None
    args = params.get("args") if isinstance(params, dict) else []
    if not isinstance(args, list):
        args = []

    headers = params.get("headers", {}) if isinstance(params, dict) else {}
    auth_headers = {str(k).lower() for k in headers} if isinstance(headers, dict) else set()
    authenticated = bool({"authorization", "proxy-authorization", "x-api-key"} & auth_headers) if url else None
    approval = _approval_value(_literal(_kw(node, "require_approval")))
    guardrails = bool(_literal(_kw(node, "tool_input_guardrails"))) or bool(
        _literal(_kw(node, "tool_output_guardrails"))
    )

    return MCPServer(
        name=alias,
        transport=MCP_TYPES[call_name],
        url=str(url) if url else None,
        command=str(command) if command else None,
        args=[str(x) for x in args],
        authenticated=authenticated,
        approval=approval,
        guardrails=guardrails,
        location=_location(path, node),
        metadata={"auth_headers": sorted(auth_headers)},
    )


def _decorated_function_tool(path: Path, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Tool | None:
    for decorator in node.decorator_list:
        decorator_name: str | None = None
        needs_approval: bool | None = None
        guardrails = False

        if isinstance(decorator, ast.Call):
            decorator_name = _call_name(decorator.func)
            needs_approval = _approval_value(_literal(_kw(decorator, "needs_approval")))
            guardrails = bool(_literal(_kw(decorator, "tool_input_guardrails"))) or bool(
                _literal(_kw(decorator, "tool_output_guardrails"))
            )
        else:
            decorator_name = _call_name(decorator)

        if decorator_name in {"function_tool", "tool"}:
            tool = Tool(
                name=node.name,
                kind="function",
                capabilities=infer_capabilities(node.name),
                approval=needs_approval,
                guardrails=guardrails,
                location=_location(path, node),
            )
            # Infer fixed network destinations from literal URLs in the function body.
            for child in ast.walk(node):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    value = child.value
                    if value.startswith(("http://", "https://")):
                        parsed = urlparse(value)
                        if parsed.hostname:
                            tool.destinations.append(
                                NetworkDestination(target=value, restricted=True, location=_location(path, child))
                            )
            return tool
    return None


def _resolve_sequence(expr: ast.AST | None, sequences: dict[str, list[ast.AST]]) -> list[ast.AST]:
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return list(expr.elts)
    if isinstance(expr, ast.Name):
        return list(sequences.get(expr.id, []))
    return []


def scan_python_file(path: Path) -> Graph:
    graph = Graph()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return graph

    tools: dict[str, Tool] = {}
    mcp_servers: dict[str, MCPServer] = {}
    sequences: dict[str, list[ast.AST]] = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool = _decorated_function_tool(path, node)
            if tool:
                tools[node.name] = tool

        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets: list[ast.AST] = node.targets if isinstance(node, ast.Assign) else [node.target]
            alias = next((target.id for target in targets if isinstance(target, ast.Name)), None)
            if not alias:
                continue
            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                sequences[alias] = list(value.elts)
                continue
            if not isinstance(value, ast.Call):
                continue
            tool = _tool_from_call(path, value, alias)
            if tool:
                tools[alias] = tool
            server = _mcp_from_call(path, value, alias)
            if server:
                mcp_servers[alias] = server

        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if not isinstance(item.context_expr, ast.Call) or not isinstance(item.optional_vars, ast.Name):
                    continue
                alias = item.optional_vars.id
                server = _mcp_from_call(path, item.context_expr, alias)
                if server:
                    mcp_servers[alias] = server

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node.func) != "Agent":
            continue

        name_value = _literal(_kw(node, "name"))
        instructions = _literal(_kw(node, "instructions"))
        agent = Agent(
            name=str(name_value or f"agent@{getattr(node, 'lineno', 1)}"),
            location=_location(path, node),
            metadata={"instructions": instructions} if isinstance(instructions, str) else {},
        )

        for element in _resolve_sequence(_kw(node, "tools"), sequences):
            if isinstance(element, ast.Name) and element.id in tools:
                agent.tools.append(tools[element.id])
            elif isinstance(element, ast.Call):
                direct_tool = _tool_from_call(path, element)
                if direct_tool:
                    agent.tools.append(direct_tool)

        for element in _resolve_sequence(_kw(node, "mcp_servers"), sequences):
            if isinstance(element, ast.Name) and element.id in mcp_servers:
                agent.mcp_servers.append(mcp_servers[element.id])

        # Infer inbound untrusted content only for tools whose names/kinds imply retrieval/browser input.
        inbound_markers = ("search", "browser", "fetch", "retrieve", "web_read", "read_email", "inbox", "webhook")
        inbound_tools = [
            t for t in agent.tools
            if t.kind == "hosted_mcp" or any(marker in t.name.lower() for marker in inbound_markers)
        ]
        if inbound_tools or any(server.url for server in agent.mcp_servers):
            agent.inputs.append(
                InputSource(
                    name="external-content",
                    trust="untrusted",
                    kind="web",
                    location=agent.location,
                    metadata={"inferred": True},
                )
            )

        graph.agents.append(agent)

    bound_tool_ids = {id(tool) for agent in graph.agents for tool in agent.tools}
    bound_server_ids = {id(server) for agent in graph.agents for server in agent.mcp_servers}
    graph.unbound_tools.extend(tool for tool in tools.values() if id(tool) not in bound_tool_ids)
    graph.unbound_mcp_servers.extend(server for server in mcp_servers.values() if id(server) not in bound_server_ids)
    return graph
