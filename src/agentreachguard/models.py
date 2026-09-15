from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Unknown severity: {value}") from exc

    def label(self) -> str:
        return self.name.lower()


@dataclass(slots=True)
class SourceLocation:
    path: Path
    line: int = 1
    column: int = 1


@dataclass(slots=True)
class ResourceScope:
    kind: str
    selector: str
    access: set[str] = field(default_factory=set)
    classification: str = "internal"
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NetworkDestination:
    target: str
    direction: str = "outbound"
    restricted: bool = True
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class InputSource:
    name: str
    trust: str = "trusted"
    kind: str = "user"
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Identity:
    name: str
    provider: str = "generic"
    roles: set[str] = field(default_factory=set)
    permissions: set[str] = field(default_factory=set)
    oauth_scopes: set[str] = field(default_factory=set)
    resource_scope: str | None = None
    credential_source: str | None = None
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def effective_permissions(self) -> set[str]:
        return set(self.permissions) | {f"role:{role}" for role in self.roles} | {
            f"oauth:{scope}" for scope in self.oauth_scopes
        }


@dataclass(slots=True)
class Tool:
    name: str
    kind: str
    capabilities: set[str] = field(default_factory=set)
    approval: bool | None = None
    guardrails: bool = False
    resources: list[ResourceScope] = field(default_factory=list)
    destinations: list[NetworkDestination] = field(default_factory=list)
    identity: str | None = None
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class MCPServer:
    name: str
    transport: str
    url: str | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    authenticated: bool | None = None
    approval: bool | None = None
    guardrails: bool = False
    allowed_tools: list[str] = field(default_factory=list)
    denied_tools: list[str] = field(default_factory=list)
    identity: str | None = None
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DataSource:
    name: str
    classification: str = "internal"
    capability: str = "data.read"
    selector: str | None = None
    location: SourceLocation | None = None


@dataclass(slots=True)
class AgentPolicy:
    required_capabilities: set[str] = field(default_factory=set)
    denied_capabilities: set[str] = field(default_factory=set)
    allowed_resources: list[str] = field(default_factory=list)
    allowed_destinations: list[str] = field(default_factory=list)
    require_approval_for: set[str] = field(default_factory=set)
    max_privileged_capabilities: int | None = None


@dataclass(slots=True)
class Agent:
    name: str
    tools: list[Tool] = field(default_factory=list)
    mcp_servers: list[MCPServer] = field(default_factory=list)
    data_sources: list[DataSource] = field(default_factory=list)
    inputs: list[InputSource] = field(default_factory=list)
    identities: list[Identity] = field(default_factory=list)
    network: list[NetworkDestination] = field(default_factory=list)
    policy: AgentPolicy = field(default_factory=AgentPolicy)
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def capabilities(self) -> set[str]:
        result: set[str] = set()
        for tool in self.tools:
            result.update(tool.capabilities)
        for source in self.data_sources:
            result.add(source.capability)
        for server in self.mcp_servers:
            result.add("mcp.remote" if server.url else "mcp.local")
            if server.url:
                result.add("network.external")
        return result

    @property
    def effective_resources(self) -> list[ResourceScope]:
        resources: list[ResourceScope] = []
        resources.extend(
            ResourceScope(
                kind="data",
                selector=source.selector or source.name,
                access={source.capability},
                classification=source.classification,
                location=source.location,
            )
            for source in self.data_sources
        )
        for tool in self.tools:
            resources.extend(tool.resources)
        return resources

    @property
    def effective_destinations(self) -> list[NetworkDestination]:
        destinations = list(self.network)
        for tool in self.tools:
            destinations.extend(tool.destinations)
        for server in self.mcp_servers:
            if server.url:
                destinations.append(
                    NetworkDestination(
                        target=server.url,
                        direction="outbound",
                        restricted=True,
                        location=server.location,
                        metadata={"source": "mcp"},
                    )
                )
        return destinations


@dataclass(slots=True)
class AttackPath:
    path_id: str
    title: str
    agent: str
    nodes: list[str]
    severity: Severity
    rationale: str
    location: SourceLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Graph:
    agents: list[Agent] = field(default_factory=list)
    unbound_tools: list[Tool] = field(default_factory=list)
    unbound_mcp_servers: list[MCPServer] = field(default_factory=list)
    identities: list[Identity] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)

    def all_tools(self) -> list[Tool]:
        tools = list(self.unbound_tools)
        for agent in self.agents:
            tools.extend(agent.tools)
        return tools

    def all_mcp_servers(self) -> list[MCPServer]:
        servers = list(self.unbound_mcp_servers)
        for agent in self.agents:
            servers.extend(agent.mcp_servers)
        return servers

    def all_identities(self) -> list[Identity]:
        identities = list(self.identities)
        for agent in self.agents:
            identities.extend(agent.identities)
        return identities


@dataclass(slots=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    recommendation: str
    layer: int = 1
    location: SourceLocation | None = None
    agent: str | None = None
    evidence: list[str] = field(default_factory=list)
    standards: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label(),
            "title": self.title,
            "message": self.message,
            "recommendation": self.recommendation,
            "layer": self.layer,
            "agent": self.agent,
            "evidence": self.evidence,
            "standards": self.standards,
            "location": (
                {
                    "path": str(self.location.path),
                    "line": self.location.line,
                    "column": self.location.column,
                }
                if self.location
                else None
            ),
        }
