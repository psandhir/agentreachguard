from __future__ import annotations

from pathlib import Path

from agentreachguard.adapters.adk_config import scan_adk_config, scan_adk_env
from agentreachguard.adapters.google_adk import is_google_adk_file
from agentreachguard.adapters.google_adk import scan_python_file as scan_google_adk_python
from agentreachguard.adapters.iac_identity import scan_terraform
from agentreachguard.adapters.manifest import MANIFEST_FILENAMES, scan_manifest
from agentreachguard.adapters.mcp_config import MCP_FILENAMES, scan_mcp_config
from agentreachguard.adapters.openai_agents import scan_python_file
from agentreachguard.analysis import build_attack_paths
from agentreachguard.models import Agent, Graph, Identity, NetworkDestination, ResourceScope, Tool
from agentreachguard.rules.builtin import evaluate

DEFAULT_IGNORES = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}


def _merge(target: Graph, source: Graph) -> None:
    target.agents.extend(source.agents)
    target.unbound_tools.extend(source.unbound_tools)
    target.unbound_mcp_servers.extend(source.unbound_mcp_servers)
    target.identities.extend(source.identities)


def _merge_tool(existing: Tool, incoming: Tool) -> None:
    existing.capabilities.update(incoming.capabilities)
    if existing.approval is not False:
        if incoming.approval is False:
            existing.approval = False
        elif incoming.approval is True:
            existing.approval = True
    existing.guardrails = existing.guardrails or incoming.guardrails
    if existing.kind == "generic" and incoming.kind != "generic":
        existing.kind = incoming.kind
        existing.location = incoming.location or existing.location
    if incoming.identity:
        existing.identity = incoming.identity
    existing.resources.extend(r for r in incoming.resources if r not in existing.resources)
    existing.destinations.extend(d for d in incoming.destinations if d not in existing.destinations)
    existing.metadata.update(incoming.metadata)


def _merge_identity(existing: Identity, incoming: Identity) -> None:
    existing.roles.update(incoming.roles)
    existing.permissions.update(incoming.permissions)
    existing.oauth_scopes.update(incoming.oauth_scopes)
    existing.resource_scope = incoming.resource_scope or existing.resource_scope
    existing.credential_source = incoming.credential_source or existing.credential_source
    existing.metadata.update(incoming.metadata)


def _consolidate_global_identities(graph: Graph) -> None:
    by_key: dict[tuple[str, str], Identity] = {}
    for identity in graph.identities:
        key = (identity.name, identity.provider)
        if key not in by_key:
            by_key[key] = identity
        else:
            _merge_identity(by_key[key], identity)
    graph.identities = list(by_key.values())


def _consolidate_agents(graph: Graph) -> None:
    """Merge framework source and AgentReachGuard manifest declarations by agent name."""
    by_name: dict[str, Agent] = {}
    for incoming in graph.agents:
        existing = by_name.get(incoming.name)
        if existing is None:
            by_name[incoming.name] = incoming
            continue

        tool_by_name = {tool.name: tool for tool in existing.tools}
        for tool in incoming.tools:
            current = tool_by_name.get(tool.name)
            if current is None:
                existing.tools.append(tool)
                tool_by_name[tool.name] = tool
            else:
                _merge_tool(current, tool)

        source_keys = {(s.name, s.classification, s.capability, s.selector) for s in existing.data_sources}
        for source in incoming.data_sources:
            key = (source.name, source.classification, source.capability, source.selector)
            if key not in source_keys:
                existing.data_sources.append(source)
                source_keys.add(key)

        input_keys = {(i.name, i.trust, i.kind) for i in existing.inputs}
        for item in incoming.inputs:
            key = (item.name, item.trust, item.kind)
            if key not in input_keys:
                existing.inputs.append(item)
                input_keys.add(key)

        server_names = {server.name for server in existing.mcp_servers}
        for server in incoming.mcp_servers:
            if server.name not in server_names:
                existing.mcp_servers.append(server)
                server_names.add(server.name)

        identity_by_name = {identity.name: identity for identity in existing.identities}
        for identity in incoming.identities:
            if identity.name in identity_by_name:
                _merge_identity(identity_by_name[identity.name], identity)
            else:
                existing.identities.append(identity)
                identity_by_name[identity.name] = identity

        existing.network.extend(d for d in incoming.network if d not in existing.network)
        # A manifest policy is authoritative when it declares any constraints.
        p = incoming.policy
        if (
            p.required_capabilities
            or p.denied_capabilities
            or p.allowed_resources
            or p.allowed_destinations
            or p.require_approval_for
            or p.max_privileged_capabilities is not None
        ):
            existing.policy = p
        existing.metadata.update(incoming.metadata)

    graph.agents = list(by_name.values())


def _propagate_adk_delegation(graph: Graph) -> None:
    """Propagate child-agent effective authority into delegating ADK parents.

    This turns sub_agents/AgentTool relationships into concrete capabilities so
    Layers 2-5 can reason about privilege reachable through delegation.
    """
    by_name = {agent.name: agent for agent in graph.agents}
    # ADK Agent Config and multi-file Python projects often refer to children by
    # config/module name rather than the child's runtime `name`. Build stable
    # aliases from source locations so privilege still propagates cross-file.
    by_alias: dict[str, Agent] = dict(by_name)
    for agent in graph.agents:
        if agent.location:
            source = agent.location.path
            aliases = {source.stem, source.parent.name}
            aliases.update({f"{a}_agent" for a in list(aliases) if a and a != "."})
            aliases.add(str(source.resolve()))
            for alias in aliases:
                if alias and alias not in by_alias:
                    by_alias[alias] = agent
    for _ in range(max(1, len(graph.agents))):
        changed = False
        for parent in graph.agents:
            targets = list(parent.metadata.get("delegates_to") or [])
            existing_targets = {t.metadata.get("delegate_target") for t in parent.tools if t.kind == "delegated_agent"}
            for target_name in targets:
                target = str(target_name)
                child = by_name.get(target) or by_alias.get(target)
                if child is None:
                    # Common ADK naming convention: specialist_agent variable
                    # defined in specialist/agent.py or specialist.py.
                    base = target.removesuffix("_agent")
                    child = by_alias.get(base) or by_alias.get(f"{base}_agent")
                if child is None or child is parent or child.name in existing_targets:
                    continue
                delegated = Tool(
                    name=f"delegate:{child.name}",
                    kind="delegated_agent",
                    capabilities=set(child.capabilities) | {"agent.delegate"},
                    approval=None,
                    guardrails=bool(child.metadata.get("safety_plugin")) or bool((child.metadata.get("callbacks") or {}).get("before_tool_callback")),
                    resources=[
                        ResourceScope(
                            kind=r.kind, selector=r.selector, access=set(r.access), classification=r.classification,
                            location=r.location, metadata={**r.metadata, "via_agent": child.name}
                        ) for r in child.effective_resources
                    ],
                    destinations=[
                        NetworkDestination(
                            target=d.target, direction=d.direction, restricted=d.restricted, location=d.location,
                            metadata={**d.metadata, "via_agent": child.name}
                        ) for d in child.effective_destinations
                    ],
                    location=parent.location,
                    metadata={"framework": "google-adk", "delegate_target": child.name, "transitive": True},
                )
                parent.tools.append(delegated)
                existing_targets.add(child.name)
                changed = True
        if not changed:
            break


def _link_global_identities(graph: Graph) -> None:
    """Enrich agent/tool identity references with matching IaC-discovered identities."""
    by_name = {identity.name: identity for identity in graph.identities}
    for agent in graph.agents:
        existing = {identity.name for identity in agent.identities}
        referenced = {tool.identity for tool in agent.tools if tool.identity}
        referenced.update(server.identity for server in agent.mcp_servers if server.identity)
        for name in referenced:
            if name and name in by_name and name not in existing:
                agent.identities.append(by_name[name])


def scan(path: Path) -> tuple[Graph, list]:
    root = path.resolve()
    graph = Graph()

    if root.is_file():
        candidates = [root]
    else:
        candidates = [
            p
            for p in root.rglob("*")
            if p.is_file() and not any(part in DEFAULT_IGNORES for part in p.relative_to(root).parts)
        ]

    for candidate in candidates:
        if candidate.suffix == ".py":
            if is_google_adk_file(candidate):
                _merge(graph, scan_google_adk_python(candidate))
            else:
                _merge(graph, scan_python_file(candidate))
        elif candidate.suffix == ".tf":
            _merge(graph, scan_terraform(candidate))
        elif candidate.name in MCP_FILENAMES:
            _merge(graph, scan_mcp_config(candidate))
        elif candidate.name in MANIFEST_FILENAMES:
            _merge(graph, scan_manifest(candidate))
        elif candidate.suffix.lower() in {".yaml", ".yml"}:
            _merge(graph, scan_adk_config(candidate))
        elif candidate.name == ".env" or candidate.name.startswith(".env."):
            _merge(graph, scan_adk_env(candidate))

    _consolidate_global_identities(graph)
    _consolidate_agents(graph)
    _propagate_adk_delegation(graph)
    _link_global_identities(graph)
    graph.attack_paths = build_attack_paths(graph)
    return graph, evaluate(graph)
