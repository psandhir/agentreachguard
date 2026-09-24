from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from urllib.parse import urlparse

from horustrace.models import Graph, Identity, MCPServer


def _module_name(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).with_suffix("")
    except ValueError:
        relative = Path(path.stem)
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _module_matches(path: Path, root: Path, import_module: str) -> bool:
    module = _module_name(path, root)
    return module == import_module or module.endswith(f".{import_module}")


def resolve_imported_mcp_placeholders(graph: Graph, root: Path) -> None:
    """Bind imported MCP server objects only when the repository match is unique."""
    concrete = [
        server
        for server in graph.unbound_mcp_servers
        if not server.metadata.get("placeholder")
    ]
    used: set[int] = set()

    for agent in graph.agents:
        for index, server in enumerate(list(agent.mcp_servers)):
            if not server.metadata.get("placeholder"):
                continue
            import_module = server.metadata.get("import_module")
            if not isinstance(import_module, str) or not import_module:
                continue
            matches = [
                candidate
                for candidate in concrete
                if candidate.name == server.name
                and candidate.location is not None
                and _module_matches(candidate.location.path, root, import_module)
            ]
            if len(matches) != 1:
                server.metadata["context_binding"] = "ambiguous_or_unresolved"
                continue

            source = matches[0]
            resolved = deepcopy(source)
            resolved.metadata = {
                **resolved.metadata,
                "repository_resolved": True,
                "import_module": import_module,
                "imported_binding": True,
            }
            agent.mcp_servers[index] = resolved
            used.add(id(source))

    if used:
        graph.unbound_mcp_servers = [
            server for server in graph.unbound_mcp_servers if id(server) not in used
        ]



def resolve_fast_agent_mcp_references(graph: Graph) -> None:
    """Bind FastAgent servers=[...] references when the MCP server name is unique.

    The binding is repository-static and intentionally name-scoped only after
    FastAgent has explicitly declared the server reference. Ambiguous duplicate
    server names remain unresolved.
    """
    concrete_by_name: dict[str, list[MCPServer]] = {}
    for server in graph.unbound_mcp_servers:
        if server.metadata.get("placeholder"):
            continue
        concrete_by_name.setdefault(server.name, []).append(server)

    used: set[int] = set()
    for agent in graph.agents:
        if agent.metadata.get("framework") != "fast-agent":
            continue
        refs = agent.metadata.get("mcp_server_refs")
        if not isinstance(refs, list):
            continue

        tool_filters = agent.metadata.get("mcp_tool_filters")
        if not isinstance(tool_filters, dict):
            tool_filters = {}

        for ref in refs:
            if not isinstance(ref, str) or not ref:
                continue
            matches = concrete_by_name.get(ref, [])
            if len(matches) != 1:
                for server in matches:
                    server.metadata.setdefault(
                        "context_binding",
                        "ambiguous_fast_agent_reference",
                    )
                continue

            source = matches[0]
            resolved = deepcopy(source)
            configured_filter = tool_filters.get(ref)
            if isinstance(configured_filter, list) and all(
                isinstance(item, str) for item in configured_filter
            ):
                if resolved.allowed_tools:
                    configured = set(configured_filter)
                    resolved.allowed_tools = [
                        item
                        for item in resolved.allowed_tools
                        if item in configured
                    ]
                else:
                    resolved.allowed_tools = list(configured_filter)
                resolved.metadata["fast_agent_tool_filter"] = list(
                    configured_filter
                )

            resolved.metadata = {
                **resolved.metadata,
                "binding_origin": "fast_agent_servers_reference",
                "effective_agent": agent.name,
                "fast_agent_server_reference": ref,
                "repository_resolved": True,
            }
            agent.mcp_servers.append(resolved)
            used.add(id(source))

    if used:
        graph.unbound_mcp_servers = [
            server
            for server in graph.unbound_mcp_servers
            if id(server) not in used
        ]

def _authority_scope(server: MCPServer) -> str:
    if server.allowed_tools:
        return "explicit_allowlist"
    if server.denied_tools:
        return "denylist_only"
    if server.metadata.get("dynamic_tool_filter"):
        return "dynamic_filter"
    return "unrestricted_or_unknown"


def _provider(server: MCPServer) -> str:
    if server.url:
        hostname = urlparse(server.url).hostname or ""
        if hostname:
            return hostname
    return "mcp"


def reconstruct_mcp_context(graph: Graph) -> None:
    """Attach effective-agent, auth, tool-scope and destination context to MCP."""
    for server in graph.unbound_mcp_servers:
        server.metadata.setdefault("context_binding", "unbound")

    for agent in graph.agents:
        known_identity_names = {identity.name for identity in agent.identities}
        for server in agent.mcp_servers:
            server.metadata["context_binding"] = "bound"
            server.metadata["effective_agent"] = agent.name
            server.metadata["authority_scope"] = _authority_scope(server)
            server.metadata["tool_authority"] = {
                "allowed": list(server.allowed_tools),
                "denied": list(server.denied_tools),
            }
            server.metadata["destination"] = server.url or server.command
            server.metadata["auth_state"] = (
                "authenticated"
                if server.authenticated is True
                else "unauthenticated"
                if server.authenticated is False
                else "unknown"
            )

            credential_source = server.metadata.get("credential_source")
            if (
                isinstance(credential_source, str)
                and credential_source
                and server.identity is None
            ):
                identity_name = f"{agent.name}:{server.name}:mcp-auth"
                server.identity = identity_name
                if identity_name not in known_identity_names:
                    agent.identities.append(
                        Identity(
                            name=identity_name,
                            provider=_provider(server),
                            credential_source=credential_source,
                            location=server.location,
                            metadata={
                                "framework": server.metadata.get("framework"),
                                "source": "mcp_auth",
                                "mcp_server": server.name,
                                "effective_agent": agent.name,
                            },
                        )
                    )
                    known_identity_names.add(identity_name)
