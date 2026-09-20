from __future__ import annotations

import ast
import json
from copy import deepcopy
from pathlib import Path

import yaml

from agentreachguard.adapters.adk_config import scan_adk_config, scan_adk_env
from agentreachguard.adapters.iac_identity import scan_terraform
from agentreachguard.adapters.manifest import MANIFEST_FILENAMES, scan_manifest
from agentreachguard.adapters.mcp_config import MCP_FILENAMES, scan_mcp_config
from agentreachguard.adapters.registry import scan_python_file
from agentreachguard.adapters.repository_adk import enrich_repository_graph
from agentreachguard.adg import build_adg
from agentreachguard.analysis import build_attack_paths
from agentreachguard.config import ScanConfig
from agentreachguard.config import apply as apply_config
from agentreachguard.coverage import add_diagnostic, diagnose_dynamic_constructs, diagnose_python
from agentreachguard.flow import analyze_repository_flows
from agentreachguard.heuristics import PRIVILEGED_CAPABILITIES
from agentreachguard.limits import (
    MAX_FILE_SIZE_BYTES,
    MAX_FILES_VISITED,
    ScanLimitError,
    validate_json_safety,
    validate_yaml_safety,
)
from agentreachguard.models import (
    Agent,
    EvidenceFact,
    Graph,
    Identity,
    NetworkDestination,
    ResourceScope,
    ScanDiagnostic,
    SourceLocation,
    Tool,
)
from agentreachguard.path_safety import canonical_root, is_within_root
from agentreachguard.provenance import annotate, attach_findings, context
from agentreachguard.rules.builtin import evaluate
from agentreachguard.suppressions import SUPPRESSION_FILENAMES, SuppressionError
from agentreachguard.suppressions import apply as apply_suppressions


class ScannerError(ValueError):
    """A scan could not continue safely."""

DEFAULT_IGNORES = {
    ".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__",
}
IGNORE_MARKER = ".agentreachguard-ignore"


def _ignored(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if any(part in DEFAULT_IGNORES for part in relative.parts):
        return True
    current = path.parent
    while current != root and root in current.parents:
        if (current / IGNORE_MARKER).exists():
            return True
        current = current.parent
    return False


def _merge(target: Graph, source: Graph, path: Path) -> None:
    annotate(source, path)
    # Manifest overlays must not alter another agent sharing the same source tool.
    for agent in source.agents:
        agent.tools = deepcopy(agent.tools)
    target.agents.extend(source.agents)
    target.unbound_tools.extend(source.unbound_tools)
    target.unbound_mcp_servers.extend(source.unbound_mcp_servers)
    target.identities.extend(source.identities)
    for diagnostic in source.coverage.diagnostics:
        add_diagnostic(target.coverage, diagnostic)


def _merge_tool(existing: Tool, incoming: Tool) -> None:
    existing.provenance.extend(f for f in incoming.provenance if f not in existing.provenance)
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
    existing.provenance.extend(f for f in incoming.provenance if f not in existing.provenance)
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

        # Keep a framework source location when policy was discovered first;
        # delegation aliases depend on the actual module/config filename.
        if (existing.location and existing.location.path.name in MANIFEST_FILENAMES
                and incoming.location and incoming.location.path.name not in MANIFEST_FILENAMES):
            existing.location = incoming.location

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
        existing.provenance.extend(f for f in incoming.provenance if f not in existing.provenance)
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
    # Resolve edges before adding synthetic tools. Traverse original authority
    # for each edge so results are independent of scan order and cycles terminate.
    children: dict[str, list[Agent]] = {}
    for parent in graph.agents:
        children[parent.name] = []
        for target_name in parent.metadata.get("delegates_to") or []:
            target = str(target_name)
            child = by_name.get(target) or by_alias.get(target)
            if child is None:
                base = target.removesuffix("_agent")
                child = by_alias.get(base) or by_alias.get(f"{base}_agent")
            if child is None:
                add_diagnostic(graph.coverage, ScanDiagnostic(
                    "unresolved_delegation", "Delegated agent could not be resolved.", parent.location,
                ))
            if (
                child is not None and child is not parent
                and child.name not in {a.name for a in children[parent.name]}
            ):
                children[parent.name].append(child)

    authority = {
        a.name: (
            set(a.capabilities),
            a.effective_resources,
            a.effective_destinations,
            context(a),
            list(a.tools),
        )
        for a in graph.agents
    }
    for parent in graph.agents:
        for child in children[parent.name]:
            provenance = [EvidenceFact(parent.name, f"delegates_to={child.name}",
                                       "inferred", parent.location)]
            capabilities = {"agent.delegate"}
            resources: list[ResourceScope] = []
            destinations: list[NetworkDestination] = []
            privileged_tools: list[Tool] = []
            outbound_tools: list[Tool] = []
            pending = [child]
            visited = {parent.name}
            while pending:
                reachable = pending.pop()
                if reachable.name in visited:
                    continue
                visited.add(reachable.name)
                caps, scopes, targets, original_facts, original_tools = authority[reachable.name]
                for original_tool in original_tools:
                    if (
                        original_tool.capabilities & PRIVILEGED_CAPABILITIES
                        and original_tool not in privileged_tools
                    ):
                        privileged_tools.append(original_tool)
                    if (
                        {"network.external", "external.write"} & original_tool.capabilities
                        and original_tool not in outbound_tools
                    ):
                        outbound_tools.append(original_tool)
                provenance.extend(f for f in original_facts if f not in provenance)
                capabilities.update(caps)
                if children[reachable.name]:
                    capabilities.add("agent.delegate")
                for resource in scopes:
                    copied = ResourceScope(
                        kind=resource.kind, selector=resource.selector,
                        access=set(resource.access), classification=resource.classification,
                        location=resource.location,
                        metadata={**resource.metadata, "via_agent": reachable.name},
                        provenance=list(resource.provenance),
                    )
                    if copied not in resources:
                        resources.append(copied)
                for destination in targets:
                    copied_destination = NetworkDestination(
                        target=destination.target, direction=destination.direction,
                        restricted=destination.restricted, location=destination.location,
                        metadata={**destination.metadata, "via_agent": reachable.name},
                        provenance=list(destination.provenance),
                    )
                    if copied_destination not in destinations:
                        destinations.append(copied_destination)
                pending.extend(children[reachable.name])
            delegated_approval = (
                True
                if privileged_tools
                and all(tool.approval is True for tool in privileged_tools)
                else None
            )
            managed_outbound = bool(outbound_tools) and all(
                tool.metadata.get("network_scope") == "fixed_managed_service"
                for tool in outbound_tools
            )
            parent.tools.append(Tool(
                name=f"delegate:{child.name}", kind="delegated_agent",
                capabilities=capabilities, approval=delegated_approval,
                guardrails=bool(child.metadata.get("safety_plugin")) or bool(
                    (child.metadata.get("callbacks") or {}).get("before_tool_callback")
                ),
                resources=resources, destinations=destinations, location=parent.location,
                provenance=provenance,
                metadata={
                    "framework": parent.metadata.get("framework", "generic"),
                    "delegate_target": child.name,
                    "transitive": True,
                    "approval_inherited": delegated_approval is True,
                    "network_scope": (
                        "fixed_managed_service" if managed_outbound else "inherited"
                    ),
                },
            ))


def _link_global_identities(graph: Graph) -> None:
    """Enrich agent/tool identity references with matching IaC-discovered identities."""
    by_name = {identity.name: identity for identity in graph.identities}
    for agent in graph.agents:
        existing = {identity.name for identity in agent.identities}
        for identity in agent.identities:
            discovered = by_name.get(identity.name)
            if discovered is not None and discovered.provider in {identity.provider, "generic"}:
                _merge_identity(identity, discovered)
            elif discovered is not None and identity.provider == "generic":
                identity.provider = discovered.provider
                _merge_identity(identity, discovered)
        referenced = {tool.identity for tool in agent.tools if tool.identity}
        referenced.update(server.identity for server in agent.mcp_servers if server.identity)
        for name in referenced:
            if name and name in by_name and name not in existing:
                agent.identities.append(by_name[name])


def scan(
    path: Path,
    suppressions_path: Path | None = None,
    use_default_suppressions: bool = True,
    config: ScanConfig | None = None,
) -> tuple[Graph, list]:
    root = path.resolve()
    containment_root = canonical_root(root)
    graph = Graph()

    if root.is_file():
        candidates = [root]
    else:
        candidates = []
        for candidate in root.rglob("*"):
            if len(candidates) >= MAX_FILES_VISITED:
                raise ScannerError(
                    f"{root}: repository traversal exceeds the {MAX_FILES_VISITED}-file safety limit"
                )
            if candidate.is_file() and not _ignored(candidate, root):
                candidates.append(candidate)

    seen_real_paths: set[Path] = set()
    approved_python_paths: list[Path] = []
    for candidate in sorted(candidates):
        graph.coverage.files_considered += 1
        real_candidate = candidate.resolve()
        if not is_within_root(candidate, containment_root):
            graph.coverage.files_skipped += 1
            add_diagnostic(graph.coverage, ScanDiagnostic(
                "unsupported_security_construct",
                "Path resolves outside the scan root; analysis was skipped.",
                SourceLocation(candidate),
            ))
            continue
        if real_candidate in seen_real_paths:
            graph.coverage.files_skipped += 1
            continue
        supported = (candidate.suffix.lower() in {".py", ".tf", ".yaml", ".yml"}
                     or candidate.name in MCP_FILENAMES | MANIFEST_FILENAMES | SUPPRESSION_FILENAMES
                     or candidate.name == ".env" or candidate.name.startswith(".env."))
        if not supported:
            graph.coverage.files_skipped += 1
            continue
        security_config = candidate.name in MANIFEST_FILENAMES | MCP_FILENAMES | SUPPRESSION_FILENAMES
        seen_real_paths.add(real_candidate)
        try:
            if candidate.stat().st_size > MAX_FILE_SIZE_BYTES:
                raise ScanLimitError("file exceeds the configured size limit")
            text = candidate.read_text(encoding="utf-8")
            if candidate.name in MCP_FILENAMES:
                validate_json_safety(text)
                raw = json.loads(text)
                if not isinstance(raw, dict):
                    raise ValueError("invalid MCP configuration")
            elif candidate.suffix.lower() in {".yaml", ".yml"}:
                validate_yaml_safety(text)
                yaml.safe_load(text)
            elif candidate.suffix == ".py":
                ast.parse(text)
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError, yaml.YAMLError) as exc:
            if candidate.name in MANIFEST_FILENAMES and not isinstance(exc, ScanLimitError):
                # Keep the manifest adapter's established fail-closed diagnostics,
                # including its secret-safe YAML and encoding error messages.
                pass
            elif security_config:
                raise ScannerError(f"{candidate}: cannot safely analyze security configuration ({exc})") from exc
            else:
                graph.coverage.files_failed += 1
                add_diagnostic(graph.coverage, ScanDiagnostic(
                    "unsupported_security_construct" if isinstance(exc, ScanLimitError) else "parse_error",
                    "File exceeded a scanner safety limit or could not be parsed; analysis was skipped.",
                    SourceLocation(candidate, line=getattr(exc, "lineno", 1) or 1),
                ))
                continue
        graph.coverage.files_scanned += 1
        if candidate.name in SUPPRESSION_FILENAMES:
            continue
        if candidate.suffix == ".py":
            approved_python_paths.append(candidate)
            _merge(graph, scan_python_file(candidate), candidate)
            diagnose_python(candidate, graph)
        elif candidate.suffix == ".tf":
            _merge(graph, scan_terraform(candidate), candidate)
        elif candidate.name in MCP_FILENAMES:
            _merge(graph, scan_mcp_config(candidate), candidate)
        elif candidate.name in MANIFEST_FILENAMES:
            _merge(graph, scan_manifest(candidate), candidate)
        elif candidate.suffix.lower() in {".yaml", ".yml"}:
            _merge(graph, scan_adk_config(candidate), candidate)
        elif candidate.name == ".env" or candidate.name.startswith(".env."):
            _merge(graph, scan_adk_env(candidate), candidate)

    _consolidate_global_identities(graph)
    _consolidate_agents(graph)
    enrich_repository_graph(
        graph,
        root if root.is_dir() else root.parent,
        python_paths=approved_python_paths,
    )
    _consolidate_agents(graph)
    _propagate_adk_delegation(graph)
    _link_global_identities(graph)
    diagnose_dynamic_constructs(graph)
    for agent in graph.agents:
        if agent.metadata.get("dynamic_control_flow"):
            add_diagnostic(
                graph.coverage,
                ScanDiagnostic(
                    "unresolved_handoff",
                    "Dynamic graph/handoff control flow could not be fully resolved.",
                    agent.location,
                ),
            )
    if not (graph.agents or graph.all_tools() or graph.all_mcp_servers() or graph.identities):
        add_diagnostic(graph.coverage, ScanDiagnostic(
            "no_targets", "No supported agent, tool, MCP server, or identity was discovered.",
        ))
    unresolved_tools = sum(
        diagnostic.kind == "unresolved_tool"
        for diagnostic in graph.coverage.diagnostics
    )
    resolved_tools = len(graph.all_tools()) + len(graph.all_mcp_servers())
    unresolved_delegations = sum(
        diagnostic.kind == "unresolved_delegation"
        for diagnostic in graph.coverage.diagnostics
    )
    resolved_delegations = sum(
        tool.kind == "delegated_agent"
        for tool in graph.all_tools()
    )
    analysis_root = root if root.is_dir() else root.parent
    graph.flow_paths = analyze_repository_flows(analysis_root, approved_python_paths, graph)

    graph.coverage.resolution = {
        "tools": {
            "resolved_entities": resolved_tools,
            "unresolved_references": unresolved_tools,
            "ratio": (
                resolved_tools / (resolved_tools + unresolved_tools)
                if resolved_tools + unresolved_tools
                else 1.0
            ),
        },
        "delegations": {
            "resolved": resolved_delegations,
            "unresolved": unresolved_delegations,
            "ratio": (
                resolved_delegations / (resolved_delegations + unresolved_delegations)
                if resolved_delegations + unresolved_delegations
                else 1.0
            ),
        },
        "identities": {"discovered": len(graph.all_identities())},
        "external_helpers_unresolved": sum(
            diagnostic.kind == "external_helper_semantics_unresolved"
            for diagnostic in graph.coverage.diagnostics
        ),
        "flows": {
            "supported_paths": len(graph.flow_paths),
            "agent_mapped": sum(flow.agent is not None for flow in graph.flow_paths),
        },
    }

    graph.attack_paths = build_attack_paths(graph)
    graph.adg = build_adg(graph, analysis_root)
    findings = evaluate(graph)
    attach_findings(graph, findings)
    findings, disabled_rules = apply_config(config or ScanConfig(), findings)
    graph.configuration_audit = {"disabled_rules": disabled_rules}
    suppression_file = suppressions_path
    if suppression_file is None and use_default_suppressions:
        base = root if root.is_dir() else root.parent
        defaults = [base / name for name in sorted(SUPPRESSION_FILENAMES)
                    if (base / name).exists()]
        if len(defaults) > 1:
            raise SuppressionError(f"{base}: multiple default suppression files found")
        suppression_file = defaults[0] if defaults else None
    elif suppression_file is not None and not suppression_file.exists():
        raise SuppressionError(f"{suppression_file}: suppression file does not exist")
    if suppression_file is not None and not is_within_root(suppression_file, containment_root):
        raise ScannerError(f"{suppression_file}: suppression file resolves outside the scan root")
    findings, graph.suppressed_findings, graph.suppression_diagnostics = apply_suppressions(
        findings, root if root.is_dir() else root.parent, suppression_file,
    )
    return graph, findings
