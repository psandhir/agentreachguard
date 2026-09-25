"""Family-scoped authority completeness certificates.

Missing authority can be proven from positive source evidence. Excess authority needs a
stronger negative claim: that the workload surface was inspected well enough to say a
particular provider service family is not used.

This module deliberately starts narrow. It can certify *absence* of Discovery Engine
usage for a GCP workload when static source coverage is closed under a conservative set
of escape hatches. Certificates are evidence only; reconciliation does not consume them
for excess-authority decisions yet.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from horustrace.deployed_authority import deployed_authority_relationships
from horustrace.deployment_evidence import DeploymentEvidenceBundle
from horustrace.limits import MAX_FILE_SIZE_BYTES, MAX_FILES_VISITED
from horustrace.models import Agent, Graph

AUTHORITY_COMPLETENESS_SCHEMA_VERSION = 1

_RUNTIME_EXCLUDED_DIRS = {
    ".git",
    ".terraform",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    "tests",
    "test",
}

_DISCOVERY_ROLE_PREFIX = "roles/discoveryengine."
_DISCOVERY_MARKERS = {
    "discoveryengine",
    "DiscoveryEngineSearchTool",
    "VertexAiSearchTool",
}
_DYNAMIC_IMPORT_CALLS = {
    "__import__",
    "builtins.__import__",
    "importlib.import_module",
}
_DYNAMIC_EXECUTION_CALLS = {
    "eval",
    "exec",
    "compile",
    "builtins.eval",
    "builtins.exec",
    "builtins.compile",
    "os.system",
    "os.popen",
}
_GENERIC_GOOGLE_API_IMPORTS = {
    "googleapiclient.discovery",
    "google.auth.transport.requests",
}


@dataclass(frozen=True, slots=True)
class AuthorityFamilyCertificate:
    agent: str
    provider: str
    family: str
    state: str
    complete: bool
    eligible_for_excess: bool
    deployed_roles: tuple[str, ...]
    required_roles: tuple[str, ...]
    candidate_excess_roles: tuple[str, ...]
    blockers: tuple[str, ...]
    source_files_scanned: int
    family_markers: tuple[dict[str, Any], ...]
    evidence_basis: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "provider": self.provider,
            "family": self.family,
            "state": self.state,
            "complete": self.complete,
            "eligible_for_excess": self.eligible_for_excess,
            "deployed_roles": list(self.deployed_roles),
            "required_roles": list(self.required_roles),
            # These are measurement candidates only. Reconciliation does not
            # consume this field until a later, separately validated change.
            "candidate_excess_roles_not_enforced": list(
                self.candidate_excess_roles
            ),
            "blockers": list(self.blockers),
            "source_files_scanned": self.source_files_scanned,
            "family_markers": list(self.family_markers),
            "evidence_basis": list(self.evidence_basis),
            "runtime_effectiveness": "not_verified",
        }


@dataclass(frozen=True, slots=True)
class _SourceSurface:
    files_scanned: int
    family_markers: tuple[dict[str, Any], ...]
    blockers: tuple[str, ...]


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _runtime_python_files(root: Path) -> tuple[list[Path], list[str]]:
    base = root if root.is_dir() else root.parent
    files: list[Path] = []
    blockers: list[str] = []
    visited = 0

    for candidate in base.rglob("*"):
        try:
            relative = candidate.relative_to(base)
        except ValueError:
            continue
        if any(part in _RUNTIME_EXCLUDED_DIRS for part in relative.parts):
            continue
        if not candidate.is_file():
            continue

        visited += 1
        if visited > MAX_FILES_VISITED:
            blockers.append("source_file_limit_exceeded")
            break
        if candidate.suffix.lower() != ".py":
            continue
        try:
            if candidate.stat().st_size > MAX_FILE_SIZE_BYTES:
                blockers.append(f"source_file_too_large:{relative}")
                continue
        except OSError:
            blockers.append(f"source_file_unreadable:{relative}")
            continue
        files.append(candidate)

    return sorted(files), blockers


def _import_names(tree: ast.AST) -> set[str]:
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            values.add(module)
            values.update(
                f"{module}.{alias.name}".strip(".")
                for alias in node.names
                if alias.name != "*"
            )
    return values


def _discovery_marker(
    node: ast.AST,
    *,
    path: Path,
    root: Path,
) -> dict[str, Any] | None:
    marker: str | None = None
    kind: str | None = None

    if isinstance(node, (ast.Import, ast.ImportFrom)):
        imports = _import_names(node)
        value = next(
            (item for item in sorted(imports) if "discoveryengine" in item.lower()),
            None,
        )
        if value:
            marker = value
            kind = "import"
    elif isinstance(node, (ast.Name, ast.Attribute)):
        value = _call_name(node)
        if any(item.lower() in value.lower() for item in _DISCOVERY_MARKERS):
            marker = value
            kind = "symbol"
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        value = node.value
        if (
            "discoveryengine.googleapis.com" in value.lower()
            or "discoveryengine" in value.lower()
            and "googleapis.com" in value.lower()
        ):
            marker = value
            kind = "endpoint"

    if marker is None or kind is None:
        return None

    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path
    return {
        "kind": kind,
        "marker": marker,
        "path": str(relative),
        "line": getattr(node, "lineno", 1),
    }


def _source_surface(root: Path) -> _SourceSurface:
    base = root if root.is_dir() else root.parent
    files, blockers = _runtime_python_files(base)
    markers: list[dict[str, Any]] = []

    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            try:
                relative = path.relative_to(base)
            except ValueError:
                relative = path
            blockers.append(f"python_parse_unresolved:{relative}")
            continue

        imports = _import_names(tree)
        if any(
            imported == blocked
            or imported.startswith(f"{blocked}.")
            for imported in imports
            for blocked in _GENERIC_GOOGLE_API_IMPORTS
        ):
            blockers.append("generic_authenticated_google_api_surface")

        for node in ast.walk(tree):
            marker = _discovery_marker(node, path=path, root=base)
            if marker is not None and marker not in markers:
                markers.append(marker)

            if not isinstance(node, ast.Call):
                continue
            called = _call_name(node.func).lower()
            if called in _DYNAMIC_IMPORT_CALLS:
                blockers.append("dynamic_import_surface")
            if (
                called in _DYNAMIC_EXECUTION_CALLS
                or called.startswith("subprocess.")
                or "create_subprocess_" in called
            ):
                blockers.append("dynamic_execution_surface")
            if called.endswith("authorizedsession"):
                blockers.append("generic_authenticated_google_api_surface")
            if called in {"google.auth.default", "auth.default"}:
                blockers.append("generic_authenticated_google_api_surface")

    return _SourceSurface(
        files_scanned=len(files),
        family_markers=tuple(
            sorted(
                markers,
                key=lambda item: (
                    str(item["path"]),
                    int(item["line"]),
                    str(item["kind"]),
                    str(item["marker"]),
                ),
            )
        ),
        blockers=tuple(sorted(set(blockers))),
    )


def _agent_blockers(graph: Graph, agent: Agent) -> set[str]:
    blockers: set[str] = set()

    if agent.metadata.get("external_helper_semantics_unresolved"):
        blockers.add("unresolved_agent_helper")
    if agent.metadata.get("unresolved_helpers"):
        blockers.add("unresolved_agent_helper")
    if agent.metadata.get("dynamic_control_flow"):
        blockers.add("dynamic_agent_control_flow")

    for tool in agent.tools:
        if {"process.execute", "computer.control"} & set(tool.capabilities):
            blockers.add("agent_dynamic_execution_capability")
    for server in agent.mcp_servers:
        if server.command:
            blockers.add("local_mcp_execution_surface")

    coverage_blockers = {
        "unresolved_tool",
        "unresolved_handoff",
        "framework_not_normalized",
        "external_helper_semantics_unresolved",
    }
    if any(
        diagnostic.kind in coverage_blockers
        for diagnostic in graph.coverage.diagnostics
    ):
        blockers.add("scanner_unresolved_runtime_surface")

    return blockers


def _required_discovery_roles(agent: Agent) -> set[str]:
    roles: set[str] = set()
    for tool in agent.tools:
        roles.update(
            str(role)
            for role in tool.metadata.get("required_roles") or []
            if str(role).startswith(_DISCOVERY_ROLE_PREFIX)
        )
    deployment = agent.metadata.get("deployment_required_authority")
    if isinstance(deployment, dict):
        roles.update(
            str(role)
            for role in deployment.get("roles") or []
            if str(role).startswith(_DISCOVERY_ROLE_PREFIX)
        )
    return roles


def _deployed_discovery_roles(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for relationship in deployed_authority_relationships(graph, bundle):
        bucket = result.setdefault(relationship.agent, set())
        bucket.update(
            role
            for role in relationship.roles
            if role.startswith(_DISCOVERY_ROLE_PREFIX)
        )
        bucket.update(
            role
            for role in relationship.conditional_roles
            if role.startswith(_DISCOVERY_ROLE_PREFIX)
        )
    return result


def discovery_engine_completeness_certificates(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
    source_root: Path,
) -> list[AuthorityFamilyCertificate]:
    """Build conservative Discovery Engine absence certificates per workload agent."""
    surface = _source_surface(source_root)
    deployed_by_agent = _deployed_discovery_roles(graph, bundle)
    workload_agents = {
        workload.agent
        for workload in bundle.workloads
        if workload.agent
    }

    result: list[AuthorityFamilyCertificate] = []
    for agent in sorted(graph.agents, key=lambda item: item.name):
        if agent.name not in workload_agents:
            continue

        blockers = set(surface.blockers)
        blockers.update(_agent_blockers(graph, agent))
        required_roles = _required_discovery_roles(agent)
        deployed_roles = deployed_by_agent.get(agent.name, set())

        # v1 certifies only negative absence. Positive Discovery Engine usage is
        # already useful for missing-authority inference, but operation-level
        # completeness is not yet strong enough to prove a broader deployed
        # Discovery role excessive.
        if surface.family_markers:
            blockers.add("discoveryengine_usage_present")

        complete = bundle.provider == "gcp" and not blockers
        state = "complete_absence" if complete else "incomplete"
        candidate_excess = deployed_roles if complete else set()

        result.append(
            AuthorityFamilyCertificate(
                agent=agent.name,
                provider=bundle.provider,
                family="discoveryengine",
                state=state,
                complete=complete,
                eligible_for_excess=complete,
                deployed_roles=tuple(sorted(deployed_roles)),
                required_roles=tuple(sorted(required_roles)),
                candidate_excess_roles=tuple(sorted(candidate_excess)),
                blockers=tuple(sorted(blockers)),
                source_files_scanned=surface.files_scanned,
                family_markers=surface.family_markers,
                evidence_basis=(
                    "all_runtime_python_files_parsed",
                    "no_discoveryengine_source_marker",
                    "no_dynamic_import_or_execution_escape_hatch",
                    "no_unresolved_agent_or_scanner_runtime_surface",
                    "repository_declared_deployed_roles_only",
                ),
            )
        )
    return result


def authority_completeness_report(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
    source_root: Path,
) -> dict[str, Any]:
    certificates = discovery_engine_completeness_certificates(
        graph,
        bundle,
        source_root,
    )
    candidates = sum(
        len(item.candidate_excess_roles)
        for item in certificates
    )
    return {
        "schema_version": AUTHORITY_COMPLETENESS_SCHEMA_VERSION,
        "provider": bundle.provider,
        "scope": "workload_identity",
        "enforcement": "measurement_only",
        "runtime_effectiveness": "not_verified",
        "summary": {
            "certificates": len(certificates),
            "complete": sum(item.complete for item in certificates),
            "incomplete": sum(not item.complete for item in certificates),
            "eligible_for_excess": sum(
                item.eligible_for_excess for item in certificates
            ),
            "candidate_excess_roles_not_enforced": candidates,
        },
        "certificates": [item.as_dict() for item in certificates],
    }
