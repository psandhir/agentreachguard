"""First-class effective MCP authority reporting.

This module turns normalized MCP relationships into a stable, explicit product
surface. It deliberately reports unresolved dimensions rather than inferring
runtime facts that static analysis cannot prove.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from horustrace.models import Agent, Graph, Identity, MCPServer, ResourceScope, SourceLocation

MCP_AUTHORITY_SCHEMA_VERSION = 1


def _location(location: SourceLocation | None) -> dict[str, Any] | None:
    if location is None:
        return None
    return {
        "path": str(location.path),
        "line": location.line,
        "column": location.column,
    }


def _resource(resource: ResourceScope) -> dict[str, Any]:
    return {
        "kind": resource.kind,
        "selector": resource.selector,
        "access": sorted(resource.access),
        "classification": resource.classification,
        "location": _location(resource.location),
        "metadata": dict(resource.metadata),
    }


def _tool_scope(server: MCPServer) -> str:
    if server.allowed_tools:
        return "explicit_allowlist"
    if server.denied_tools:
        return "denylist_only"
    if server.metadata.get("dynamic_tool_filter"):
        return "dynamic_filter"
    return "unrestricted_or_unknown"


def _auth_state(server: MCPServer) -> str:
    if server.authenticated is True:
        return "authenticated"
    if server.authenticated is False:
        return "unauthenticated"
    return "unknown"


def _destination(server: MCPServer) -> tuple[str | None, str]:
    if server.url:
        return server.url, "fixed_remote_endpoint"
    if server.command:
        return server.command, "fixed_local_command"
    return None, "unknown"


def _identity(graph: Graph, agent: Agent, server: MCPServer) -> Identity | None:
    if not server.identity:
        return None
    for identity in [*agent.identities, *graph.identities]:
        if identity.name == server.identity:
            return identity
    return None


@dataclass(frozen=True, slots=True)
class EffectiveMCPAuthority:
    agent: str
    server: str
    transport: str
    binding_origin: str
    tool_scope: str
    effective_tools: tuple[str, ...]
    denied_tools: tuple[str, ...]
    tool_catalogue_known: bool
    auth_state: str
    auth_mechanism: str
    identity: str | None
    identity_provider: str | None
    credential_source: str | None
    destination: str | None
    destination_constraint: str
    command_args: tuple[str, ...]
    resources: tuple[dict[str, Any], ...]
    unresolved: tuple[str, ...]
    location: dict[str, Any] | None

    @property
    def fully_resolved(self) -> bool:
        return not self.unresolved

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "server": self.server,
            "transport": self.transport,
            "binding": {
                "status": "bound",
                "origin": self.binding_origin,
            },
            "tools": {
                "scope": self.tool_scope,
                "catalogue_known": self.tool_catalogue_known,
                "effective": list(self.effective_tools),
                "denied": list(self.denied_tools),
            },
            "authentication": {
                "state": self.auth_state,
                "mechanism": self.auth_mechanism,
                "identity": self.identity,
                "provider": self.identity_provider,
                "credential_source": self.credential_source,
            },
            "destination": {
                "target": self.destination,
                "constraint": self.destination_constraint,
                "args": list(self.command_args),
            },
            "resources": list(self.resources),
            "fully_resolved": self.fully_resolved,
            "unresolved": list(self.unresolved),
            "location": self.location,
        }


def effective_mcp_authorities(graph: Graph) -> list[EffectiveMCPAuthority]:
    """Return evidence-backed agent -> MCP authority relationships."""
    result: list[EffectiveMCPAuthority] = []

    for agent in graph.agents:
        for server in agent.mcp_servers:
            scope = _tool_scope(server)
            identity = _identity(graph, agent, server)
            destination, destination_constraint = _destination(server)
            auth_state = _auth_state(server)
            auth_mechanism = str(server.metadata.get("auth_mechanism") or "unknown")

            unresolved: list[str] = []
            # An explicit allowlist is the only supported static proof of the
            # positive tool catalogue currently available to the effective agent.
            if scope != "explicit_allowlist":
                unresolved.append("tool_catalogue")
            if scope == "dynamic_filter":
                unresolved.append("tool_filter")
            if auth_state == "unknown":
                unresolved.append("authentication_state")
            if auth_state == "authenticated":
                if auth_mechanism in {"unknown", "configured-auth"}:
                    unresolved.append("authentication_mechanism")
                if identity is None:
                    unresolved.append("identity")
                elif identity.credential_source is None:
                    unresolved.append("credential_source")
            if destination is None:
                unresolved.append("destination")

            result.append(
                EffectiveMCPAuthority(
                    agent=agent.name,
                    server=server.name,
                    transport=server.transport,
                    binding_origin=str(
                        server.metadata.get("binding_origin")
                        or "framework_agent_configuration"
                    ),
                    tool_scope=scope,
                    effective_tools=tuple(server.allowed_tools),
                    denied_tools=tuple(server.denied_tools),
                    tool_catalogue_known=scope == "explicit_allowlist",
                    auth_state=auth_state,
                    auth_mechanism=auth_mechanism,
                    identity=identity.name if identity else server.identity,
                    identity_provider=identity.provider if identity else None,
                    credential_source=(
                        identity.credential_source
                        if identity is not None
                        else (
                            str(server.metadata.get("credential_source"))
                            if server.metadata.get("credential_source")
                            else None
                        )
                    ),
                    destination=destination,
                    destination_constraint=destination_constraint,
                    command_args=tuple(server.args),
                    resources=tuple(_resource(resource) for resource in server.resources),
                    unresolved=tuple(sorted(set(unresolved))),
                    location=_location(server.location),
                )
            )

    return sorted(
        result,
        key=lambda item: (
            item.agent,
            item.server,
            item.destination or "",
            item.transport,
        ),
    )


def effective_mcp_authority_report(graph: Graph) -> dict[str, Any]:
    authorities = effective_mcp_authorities(graph)
    unbound = sorted(
        graph.unbound_mcp_servers,
        key=lambda server: (
            server.name,
            server.url or server.command or "",
            server.transport,
        ),
    )
    return {
        "schema_version": MCP_AUTHORITY_SCHEMA_VERSION,
        "summary": {
            "mcp_servers": len(graph.all_mcp_servers()),
            "bound_relationships": len(authorities),
            "unbound_servers": len(unbound),
            "fully_resolved_relationships": sum(
                authority.fully_resolved for authority in authorities
            ),
            "explicit_tool_scopes": sum(
                authority.tool_scope == "explicit_allowlist"
                for authority in authorities
            ),
            "identity_bound_relationships": sum(
                authority.identity is not None for authority in authorities
            ),
            "fixed_destination_relationships": sum(
                authority.destination_constraint
                in {"fixed_remote_endpoint", "fixed_local_command"}
                for authority in authorities
            ),
        },
        "authorities": [authority.as_dict() for authority in authorities],
        "unbound": [
            {
                "server": server.name,
                "transport": server.transport,
                "destination": server.url or server.command,
                "location": _location(server.location),
                "reason": str(
                    server.metadata.get("context_binding") or "unbound"
                ),
            }
            for server in unbound
        ],
    }


def render_effective_mcp_authority_console(
    graph: Graph,
    root: Path,
) -> str:
    report = effective_mcp_authority_report(graph)
    summary = report["summary"]
    lines = [
        "HorusTrace Effective MCP Authority",
        "=" * 33,
        f"Target:                 {root}",
        f"MCP servers:            {summary['mcp_servers']}",
        f"Bound relationships:    {summary['bound_relationships']}",
        f"Unbound servers:        {summary['unbound_servers']}",
        f"Fully resolved:         {summary['fully_resolved_relationships']}",
        f"Explicit tool scopes:   {summary['explicit_tool_scopes']}",
        f"Identity-bound:         {summary['identity_bound_relationships']}",
        f"Fixed destinations:     {summary['fixed_destination_relationships']}",
        "",
    ]

    authorities = report["authorities"]
    if authorities:
        lines.append("Effective relationships")
        for item in authorities:
            tools = item["tools"]
            auth = item["authentication"]
            destination = item["destination"]
            lines.append(f"  {item['agent']} -> {item['server']} ({item['transport']})")
            lines.append(
                f"    binding: {item['binding']['origin']}"
            )
            if tools["catalogue_known"]:
                effective = ", ".join(tools["effective"]) or "(empty allowlist)"
                lines.append(
                    f"    tools: {tools['scope']}; effective={effective}"
                )
            else:
                detail = (
                    ", denied=" + ", ".join(tools["denied"])
                    if tools["denied"]
                    else ""
                )
                lines.append(
                    f"    tools: {tools['scope']}; catalogue unknown{detail}"
                )
            identity = auth["identity"] or "none"
            credential = auth["credential_source"] or "n/a"
            lines.append(
                "    auth: "
                f"{auth['state']}; mechanism={auth['mechanism']}; "
                f"identity={identity}; credential={credential}"
            )
            lines.append(
                "    destination: "
                f"{destination['constraint']} "
                f"{destination['target'] or 'unknown'}"
            )
            if item["resources"]:
                rendered = ", ".join(
                    f"{resource['kind']}:{resource['selector']}"
                    for resource in item["resources"]
                )
                lines.append(f"    resources: {rendered}")
            lines.append(
                "    unresolved: "
                + (", ".join(item["unresolved"]) if item["unresolved"] else "none")
            )
        lines.append("")

    if report["unbound"]:
        lines.append("Unbound MCP servers")
        for item in report["unbound"]:
            lines.append(
                f"  {item['server']} ({item['transport']}): "
                f"{item['destination'] or 'destination unknown'}"
            )
        lines.append("")

    if not authorities and not report["unbound"]:
        lines.append("No MCP servers detected.")

    return "\n".join(lines).rstrip()
