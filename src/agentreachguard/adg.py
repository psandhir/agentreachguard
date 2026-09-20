"""Deterministic framework-agnostic Agent Dependency Graph (ADG)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentreachguard.limits import MAX_ADG_EDGES, MAX_ADG_NODES, ScanLimitError
from agentreachguard.models import Graph, SourceLocation

ADG_SCHEMA_VERSION = 1


def _relative(location: SourceLocation | None, root: Path) -> str | None:
    if location is None:
        return None
    try:
        return location.path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return location.path.name


def _location(location: SourceLocation | None, root: Path) -> dict[str, Any] | None:
    path = _relative(location, root)
    if path is None or location is None:
        return None
    return {"path": path, "line": location.line, "column": location.column}


def _stable_id(kind: str, name: str, location: SourceLocation | None, root: Path) -> str:
    payload = "\0".join((kind, name, _relative(location, root) or ""))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"adg-v1:{digest}"


def _edge_id(kind: str, source: str, target: str, attributes: dict[str, Any]) -> str:
    qualifier = json.dumps(attributes, sort_keys=True, separators=(",", ":"), default=str)
    payload = f"{kind}\0{source}\0{target}\0{qualifier}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"edge-v1:{digest}"


def _counts(values: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        result[value] = result.get(value, 0) + 1
    return dict(sorted(result.items()))


@dataclass(frozen=True, slots=True)
class ADGNode:
    node_id: str
    kind: str
    name: str
    framework: str | None = None
    location: dict[str, Any] | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind,
            "name": self.name,
            "framework": self.framework,
            "location": self.location,
            "attributes": self.attributes,
        }


@dataclass(frozen=True, slots=True)
class ADGEdge:
    edge_id: str
    kind: str
    source: str
    target: str
    location: dict[str, Any] | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.edge_id,
            "kind": self.kind,
            "source": self.source,
            "target": self.target,
            "location": self.location,
            "attributes": self.attributes,
        }


@dataclass(slots=True)
class AgentDependencyGraph:
    nodes: list[ADGNode] = field(default_factory=list)
    edges: list[ADGEdge] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        nodes = sorted((node.as_dict() for node in self.nodes), key=lambda item: item["id"])
        edges = sorted((edge.as_dict() for edge in self.edges), key=lambda item: item["id"])
        return {
            "schema_version": ADG_SCHEMA_VERSION,
            "root": ".",
            "summary": {
                "nodes": len(nodes),
                "edges": len(edges),
                "node_kinds": _counts([item["kind"] for item in nodes]),
                "edge_kinds": _counts([item["kind"] for item in edges]),
            },
            "nodes": nodes,
            "edges": edges,
        }

    def canonical_digest(self) -> str:
        payload = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


class _Builder:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.nodes: dict[str, ADGNode] = {}
        self.edges: dict[str, ADGEdge] = {}

    def node(
        self,
        kind: str,
        name: str,
        *,
        location: SourceLocation | None = None,
        framework: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> str:
        node_id = _stable_id(kind, name, location, self.root)
        if node_id in self.nodes:
            return node_id
        if len(self.nodes) >= MAX_ADG_NODES:
            raise ScanLimitError("Agent Dependency Graph exceeds the configured node limit")
        clean = {key: value for key, value in (attributes or {}).items() if value is not None}
        self.nodes[node_id] = ADGNode(
            node_id=node_id,
            kind=kind,
            name=name,
            framework=framework,
            location=_location(location, self.root),
            attributes=clean,
        )
        return node_id

    def edge(
        self,
        kind: str,
        source: str,
        target: str,
        *,
        location: SourceLocation | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        clean = {key: value for key, value in (attributes or {}).items() if value is not None}
        edge_id = _edge_id(kind, source, target, clean)
        if edge_id in self.edges:
            return
        if len(self.edges) >= MAX_ADG_EDGES:
            raise ScanLimitError("Agent Dependency Graph exceeds the configured edge limit")
        self.edges[edge_id] = ADGEdge(
            edge_id=edge_id,
            kind=kind,
            source=source,
            target=target,
            location=_location(location, self.root),
            attributes=clean,
        )


def _prompt_attributes(text: str) -> dict[str, Any]:
    return {
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "length": len(text),
        "content_included": False,
    }


def _framework(metadata: dict[str, Any]) -> str:
    return str(metadata.get("framework") or "generic")


def build_adg(graph: Graph, root: Path) -> AgentDependencyGraph:
    """Project the normalized scanner graph into ADG schema version 1."""
    builder = _Builder(root)
    identity_ids: dict[str, str] = {}
    agent_ids: dict[str, str] = {}

    identities = sorted(
        graph.all_identities(),
        key=lambda item: (
            item.name,
            item.provider,
            _relative(item.location, root) or "",
        ),
    )
    for identity in identities:
        identity_id = builder.node(
            "identity",
            identity.name,
            location=identity.location,
            framework=_framework(identity.metadata),
            attributes={
                "provider": identity.provider,
                "roles": sorted(identity.roles),
                "permissions": sorted(identity.permissions),
                "oauth_scopes": sorted(identity.oauth_scopes),
                "credential_source": identity.credential_source,
            },
        )
        identity_ids.setdefault(identity.name, identity_id)

    for agent in graph.agents:
        framework = _framework(agent.metadata)
        agent_id = builder.node(
            "agent",
            agent.name,
            location=agent.location,
            framework=framework,
            attributes={
                "agent_type": agent.metadata.get("agent_type"),
                "workflow": agent.metadata.get("workflow"),
            },
        )
        agent_ids[agent.name] = agent_id

        prompt = agent.metadata.get("instruction") or agent.metadata.get("instructions")
        if isinstance(prompt, str) and prompt:
            prompt_id = builder.node(
                "prompt",
                f"{agent.name}:system-prompt",
                location=agent.location,
                framework=framework,
                attributes=_prompt_attributes(prompt),
            )
            builder.edge("USES_PROMPT", agent_id, prompt_id, location=agent.location)

        model = agent.metadata.get("model")
        if isinstance(model, str) and model:
            model_id = builder.node(
                "model",
                model,
                location=agent.location,
                framework=framework,
            )
            builder.edge("USES_MODEL", agent_id, model_id, location=agent.location)

        for source in agent.inputs:
            input_id = builder.node(
                "input",
                f"{agent.name}:{source.name}",
                location=source.location,
                framework=framework,
                attributes={"trust": source.trust, "input_kind": source.kind},
            )
            builder.edge(
                "RECEIVES_INPUT_FROM",
                agent_id,
                input_id,
                location=source.location,
            )

        for source in agent.data_sources:
            resource_id = builder.node(
                "data_resource",
                f"{agent.name}:{source.selector or source.name}",
                location=source.location,
                framework=framework,
                attributes={
                    "selector": source.selector or source.name,
                    "classification": source.classification,
                    "capability": source.capability,
                },
            )
            builder.edge("READS_FROM", agent_id, resource_id, location=source.location)

        for identity in agent.identities:
            identity_id = identity_ids.get(identity.name)
            if identity_id is None:
                identity_id = builder.node(
                    "identity",
                    identity.name,
                    location=identity.location,
                    framework=_framework(identity.metadata),
                    attributes={"provider": identity.provider},
                )
                identity_ids[identity.name] = identity_id
            builder.edge("USES_IDENTITY", agent_id, identity_id, location=identity.location)

        for destination in agent.network:
            destination_id = builder.node(
                "network_destination",
                destination.target,
                location=destination.location,
                framework=framework,
                attributes={
                    "direction": destination.direction,
                    "restricted": destination.restricted,
                },
            )
            builder.edge(
                "CONNECTS_TO",
                agent_id,
                destination_id,
                location=destination.location,
            )

        for server in agent.mcp_servers:
            server_id = builder.node(
                "mcp_server",
                f"{agent.name}:{server.name}",
                location=server.location,
                framework=framework,
                attributes={
                    "transport": server.transport,
                    "url": server.url,
                    "authenticated": server.authenticated,
                    "approval": server.approval,
                    "allowed_tools": list(server.allowed_tools),
                },
            )
            builder.edge("INVOKES", agent_id, server_id, location=server.location)
            if server.url:
                destination_id = builder.node(
                    "network_destination",
                    server.url,
                    location=server.location,
                    framework=framework,
                    attributes={"direction": "outbound", "restricted": True},
                )
                builder.edge(
                    "CONNECTS_TO",
                    server_id,
                    destination_id,
                    location=server.location,
                )
            if server.identity:
                identity_id = identity_ids.get(server.identity)
                if identity_id:
                    builder.edge(
                        "USES_IDENTITY",
                        server_id,
                        identity_id,
                        location=server.location,
                    )

        for tool in agent.tools:
            tool_id = builder.node(
                "tool",
                f"{agent.name}:{tool.name}",
                location=tool.location,
                framework=_framework(tool.metadata) if tool.metadata else framework,
                attributes={
                    "tool_name": tool.name,
                    "tool_kind": tool.kind,
                    "capabilities": sorted(tool.capabilities),
                    "approval": tool.approval,
                    "guardrails": tool.guardrails,
                },
            )
            builder.edge("INVOKES", agent_id, tool_id, location=tool.location)
            if tool.identity:
                identity_id = identity_ids.get(tool.identity)
                if identity_id:
                    builder.edge(
                        "USES_IDENTITY",
                        tool_id,
                        identity_id,
                        location=tool.location,
                    )
            for resource in tool.resources:
                resource_id = builder.node(
                    "data_resource",
                    f"{agent.name}:{resource.kind}:{resource.selector}",
                    location=resource.location,
                    framework=framework,
                    attributes={
                        "resource_kind": resource.kind,
                        "selector": resource.selector,
                        "classification": resource.classification,
                        "access": sorted(resource.access),
                    },
                )
                edge_kind = (
                    "WRITES_TO" if "data.write" in resource.access else "READS_FROM"
                )
                builder.edge(edge_kind, tool_id, resource_id, location=resource.location)
            for destination in tool.destinations:
                destination_id = builder.node(
                    "network_destination",
                    destination.target,
                    location=destination.location or tool.location,
                    framework=framework,
                    attributes={
                        "direction": destination.direction,
                        "restricted": destination.restricted,
                        "source": destination.metadata.get("source"),
                    },
                )
                builder.edge(
                    "CONNECTS_TO",
                    tool_id,
                    destination_id,
                    location=tool.location,
                )
            if "memory" in tool.name.lower():
                memory_id = builder.node(
                    "memory",
                    f"{agent.name}:{tool.name}:memory",
                    location=tool.location,
                    framework=framework,
                    attributes={"inferred": True},
                )
                if "data.read" in tool.capabilities:
                    builder.edge("READS_MEMORY", tool_id, memory_id, location=tool.location)
                if "data.write" in tool.capabilities:
                    builder.edge("WRITES_MEMORY", tool_id, memory_id, location=tool.location)

        policy = agent.policy
        has_policy = bool(
            policy.required_capabilities
            or policy.denied_capabilities
            or policy.allowed_resources
            or policy.allowed_destinations
            or policy.require_approval_for
            or policy.max_privileged_capabilities is not None
        )
        if has_policy:
            policy_id = builder.node(
                "policy_control",
                f"{agent.name}:policy",
                location=agent.location,
                framework=framework,
                attributes={
                    "required_capabilities": sorted(policy.required_capabilities),
                    "denied_capabilities": sorted(policy.denied_capabilities),
                    "allowed_resources": list(policy.allowed_resources),
                    "allowed_destinations": list(policy.allowed_destinations),
                    "require_approval_for": sorted(policy.require_approval_for),
                    "max_privileged_capabilities": policy.max_privileged_capabilities,
                },
            )
            builder.edge("GUARDED_BY", agent_id, policy_id, location=agent.location)

    for agent in graph.agents:
        source_id = agent_ids.get(agent.name)
        if source_id is None:
            continue
        for target_name in agent.metadata.get("delegates_to") or []:
            target_id = agent_ids.get(str(target_name))
            if target_id:
                builder.edge(
                    "DELEGATES_TO",
                    source_id,
                    target_id,
                    location=agent.location,
                )

    return AgentDependencyGraph(
        nodes=list(builder.nodes.values()),
        edges=list(builder.edges.values()),
    )
