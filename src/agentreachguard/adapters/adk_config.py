from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agentreachguard.adapters.google_adk import BUILTIN_TOOL_CAPABILITIES, RETRIEVAL_TOOLS
from agentreachguard.heuristics import infer_capabilities
from agentreachguard.models import Agent, Graph, InputSource, MCPServer, SourceLocation, Tool


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(x) for x in value]
    return []


def _looks_like_adk(data: Any, path: Path) -> bool:
    if not isinstance(data, dict) or not isinstance(data.get("name"), str):
        return False
    if path.name == "root_agent.yaml":
        return True
    return any(k in data for k in ("agent_class", "model", "instruction", "sub_agents", "tools", "code_executor"))


def _tool_from_config(raw: Any, path: Path) -> tuple[Tool | None, MCPServer | None]:
    loc = SourceLocation(path=path)
    if isinstance(raw, str):
        name = raw
        caps = set(BUILTIN_TOOL_CAPABILITIES.get(name, set())) or set(infer_capabilities(name))
        tool = Tool(name=name, kind="adk_config_tool", capabilities=caps, location=loc, metadata={"framework": "google-adk", "adk_config": True})
        if name in RETRIEVAL_TOOLS:
            tool.metadata["untrusted_input"] = True
        return tool, None
    if not isinstance(raw, dict):
        return None, None

    name = str(raw.get("name") or raw.get("tool_class") or raw.get("class") or "tool")
    args = raw.get("args") if isinstance(raw.get("args"), dict) else raw
    caps = set(BUILTIN_TOOL_CAPABILITIES.get(name, set())) or set(infer_capabilities(name))
    approval = args.get("require_confirmation") if isinstance(args.get("require_confirmation"), bool) else None
    metadata: dict[str, Any] = {"framework": "google-adk", "adk_config": True, "config": raw}

    if name in {"McpToolset", "MCPToolset"}:
        connection = args.get("connection_params") or {}
        if isinstance(connection, dict):
            conn_type = str(connection.get("type") or connection.get("class") or connection.get("name") or "").lower()
            url = connection.get("url")
            server_params = connection.get("server_params") if isinstance(connection.get("server_params"), dict) else connection
            command = server_params.get("command") if isinstance(server_params, dict) else None
            cmd_args = _strings(server_params.get("args")) if isinstance(server_params, dict) else []
            transport = "stdio" if command else ("sse" if "sse" in conn_type else "streamable-http" if url else "unknown")
            headers = connection.get("headers") if isinstance(connection.get("headers"), dict) else {}
            authenticated = bool({"authorization", "x-api-key", "proxy-authorization"} & {str(k).lower() for k in headers}) if url else None
            tool_filter = args.get("tool_filter")
            allowed = _strings(tool_filter) if isinstance(tool_filter, (str, list)) else []
            return None, MCPServer(
                name=name,
                transport=transport,
                url=str(url) if url else None,
                command=str(command) if command else None,
                args=cmd_args,
                authenticated=authenticated,
                approval=approval,
                guardrails=approval is True,
                allowed_tools=allowed,
                location=loc,
                metadata=metadata,
            )

    tool = Tool(name=name, kind="adk_config_tool", capabilities=caps, approval=approval, guardrails=approval is True, location=loc, metadata=metadata)
    if name in RETRIEVAL_TOOLS:
        tool.metadata["untrusted_input"] = True
    if name == "UnsafeLocalCodeExecutor":
        tool.kind = "adk_code_executor"
        tool.capabilities.update({"process.execute", "data.read", "data.write"})
        tool.metadata.update({"sandboxed": False, "code_executor": name})
    if name in {"BuiltInCodeExecutor", "AgentEngineSandboxCodeExecutor", "GkeCodeExecutor"}:
        tool.kind = "adk_code_executor"
        tool.capabilities.update({"process.execute", "data.read", "data.write"})
        tool.guardrails = True
        tool.metadata.update({"sandboxed": True, "code_executor": name})
    return tool, None


def scan_adk_config(path: Path) -> Graph:
    graph = Graph()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return graph
    if not _looks_like_adk(data, path):
        return graph

    name = str(data.get("name"))
    agent_type = str(data.get("agent_class") or "LlmAgent")
    agent = Agent(
        name=name,
        location=SourceLocation(path=path),
        metadata={
            "framework": "google-adk",
            "agent_type": agent_type,
            "adk_config": True,
            "model": data.get("model"),
            "instruction": data.get("instruction"),
        },
    )
    if path.name == "root_agent.yaml":
        agent.inputs.append(InputSource(name="user-message", trust="untrusted", kind="user", location=agent.location))

    for raw in data.get("tools", []) or []:
        tool, server = _tool_from_config(raw, path)
        if tool:
            agent.tools.append(tool)
        if server:
            agent.mcp_servers.append(server)

    code_raw = data.get("code_executor")
    if code_raw:
        tool, _ = _tool_from_config(code_raw, path)
        if tool:
            agent.tools.append(tool)

    delegates: list[str] = []
    for sub in data.get("sub_agents", []) or []:
        if isinstance(sub, str):
            delegates.append(Path(sub).stem)
        elif isinstance(sub, dict):
            if sub.get("name"):
                delegates.append(str(sub["name"]))
            elif sub.get("config_path"):
                config_path = Path(str(sub["config_path"]))
                delegates.append(config_path.stem)
                agent.metadata.setdefault("sub_agent_configs", []).append(str((path.parent / config_path).resolve()))
    if delegates:
        agent.metadata["delegates_to"] = delegates

    callbacks = {}
    for key in ("before_agent_callback", "after_agent_callback", "before_model_callback", "after_model_callback", "before_tool_callback", "after_tool_callback"):
        if data.get(key):
            callbacks[key] = str(data[key])
    if callbacks:
        agent.metadata["callbacks"] = callbacks

    if any(t.metadata.get("untrusted_input") for t in agent.tools) or any(s.url for s in agent.mcp_servers):
        agent.inputs.append(InputSource(name="retrieved-external-content", trust="untrusted", kind="retrieval", location=agent.location, metadata={"inferred": True}))

    graph.agents.append(agent)
    return graph


def scan_adk_env(path: Path) -> Graph:
    from agentreachguard.models import Identity

    graph = Graph()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return graph
    sensitive_names = {"GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"}
    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"\'')
        if key not in sensitive_names or not value or value.startswith("<") or "YOUR_" in value.upper():
            continue
        source = "file" if key == "GOOGLE_APPLICATION_CREDENTIALS" else "hardcoded"
        graph.identities.append(
            Identity(
                name=f"adk-env:{key}",
                provider="gcp",
                credential_source=source,
                location=SourceLocation(path=path, line=line_no),
                metadata={"framework": "google-adk", "env_var": key, "value_redacted": True},
            )
        )
    return graph
