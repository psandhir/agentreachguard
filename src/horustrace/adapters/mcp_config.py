from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from horustrace.models import Graph, MCPServer, SourceLocation

MCP_FILENAMES = {"mcp.json", ".mcp.json", "mcp-config.json", "mcp_config.json"}


def _auth_from_config(config: dict[str, Any]) -> tuple[bool | None, list[str]]:
    headers = config.get("headers")
    auth_keys: list[str] = []
    if isinstance(headers, dict):
        normalized = {str(key).lower() for key in headers}
        auth_keys = sorted(
            normalized
            & {
                "authorization",
                "proxy-authorization",
                "x-api-key",
                "x-goog-api-key",
            }
        )
        if auth_keys:
            return True, auth_keys
    if config.get("authorization"):
        return True, ["authorization"]
    if config.get("oauth"):
        return True, ["oauth"]
    if config.get("token"):
        return True, ["token"]
    # A parsed static MCP configuration with no recognised auth field
    # is evidence that authentication is absent. None is reserved for
    # genuinely dynamic/unresolved authentication configuration.
    return False, auth_keys


def scan_mcp_config(path: Path) -> Graph:
    graph = Graph()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return graph

    servers = raw.get("mcpServers") or raw.get("servers") or {}
    if not isinstance(servers, dict):
        return graph

    for name, config in servers.items():
        if not isinstance(config, dict):
            continue
        url = config.get("url") or config.get("serverUrl")
        command = config.get("command")
        args = config.get("args") or []
        if not isinstance(args, list):
            args = []
        transport = str(config.get("transport") or ("stdio" if command else "http" if url else "unknown"))
        authenticated, auth_keys = _auth_from_config(config)
        allowed_tools = config.get("allowedTools") or config.get("allowed_tools") or []
        denied_tools = config.get("deniedTools") or config.get("denied_tools") or []
        graph.unbound_mcp_servers.append(
            MCPServer(
                name=str(name),
                transport=transport,
                url=str(url) if url else None,
                command=str(command) if command else None,
                args=[str(item) for item in args],
                authenticated=authenticated,
                approval=None,
                allowed_tools=[str(v) for v in allowed_tools] if isinstance(allowed_tools, list) else [],
                denied_tools=[str(v) for v in denied_tools] if isinstance(denied_tools, list) else [],
                location=SourceLocation(path=path),
                metadata={"raw_keys": sorted(config.keys()), "auth_keys": auth_keys},
            )
        )
    return graph
