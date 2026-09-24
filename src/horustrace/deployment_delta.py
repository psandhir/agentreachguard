"""Change-aware deployed-authority reconciliation for v0.8."""
from __future__ import annotations

from typing import Any

from horustrace.authority_reconciliation import authority_reconciliation_report
from horustrace.deployment_evidence import DeploymentEvidenceBundle
from horustrace.models import Graph

DEPLOYMENT_AUTHORITY_DELTA_SCHEMA_VERSION = 1


def _index(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["agent"]: item for item in report["agents"]}


def _values(item: dict[str, Any] | None, section: str, dimension: str) -> set[str]:
    if item is None:
        return set()
    return set((item.get(section) or {}).get(dimension) or [])


def _unresolved(item: dict[str, Any] | None) -> set[str]:
    return set((item or {}).get("unresolved") or [])


def _classify_permissions(permissions: set[str]) -> list[str]:
    boundaries: set[str] = set()
    for permission in permissions:
        lowered = permission.lower()
        if "secretmanager" in lowered or ".secrets." in lowered:
            boundaries.add("secret_access")
        if "setiampolicy" in lowered or "serviceaccounts.actas" in lowered:
            boundaries.add("identity_or_iam_mutation")
        if lowered.endswith(".delete") or ".delete" in lowered:
            boundaries.add("destructive_mutation")
        if any(
            marker in lowered
            for marker in (".create", ".update", ".write", ".set", ".publish", ".send")
        ):
            boundaries.add("persistent_or_external_mutation")
    return sorted(boundaries)


def deployment_authority_delta(
    graph: Graph,
    base: DeploymentEvidenceBundle,
    head: DeploymentEvidenceBundle,
) -> dict[str, Any]:
    """Compare two deployment evidence snapshots against the same source graph."""
    base_report = authority_reconciliation_report(graph, base)
    head_report = authority_reconciliation_report(graph, head)
    base_index = _index(base_report)
    head_index = _index(head_report)
    agents: list[dict[str, Any]] = []

    for agent in sorted(set(base_index) | set(head_index)):
        before = base_index.get(agent)
        after = head_index.get(agent)

        before_roles = _values(before, "deployed", "roles")
        after_roles = _values(after, "deployed", "roles")
        before_permissions = _values(before, "deployed", "permissions")
        after_permissions = _values(after, "deployed", "permissions")
        before_conditional_roles = _values(before, "deployed", "conditional_roles")
        after_conditional_roles = _values(after, "deployed", "conditional_roles")
        before_conditional_permissions = _values(
            before, "deployed", "conditional_permissions"
        )
        after_conditional_permissions = _values(
            after, "deployed", "conditional_permissions"
        )
        before_excess_roles = _values(before, "excess", "roles")
        after_excess_roles = _values(after, "excess", "roles")
        before_excess_permissions = _values(before, "excess", "permissions")
        after_excess_permissions = _values(after, "excess", "permissions")
        before_unresolved = _unresolved(before)
        after_unresolved = _unresolved(after)

        added_permissions = after_permissions - before_permissions
        introduced_excess_permissions = after_excess_permissions - before_excess_permissions
        item = {
            "agent": agent,
            "deployed": {
                "roles_added": sorted(after_roles - before_roles),
                "roles_removed": sorted(before_roles - after_roles),
                "permissions_added": sorted(added_permissions),
                "permissions_removed": sorted(before_permissions - after_permissions),
            },
            "excess": {
                "roles_introduced": sorted(after_excess_roles - before_excess_roles),
                "roles_resolved": sorted(before_excess_roles - after_excess_roles),
                "permissions_introduced": sorted(introduced_excess_permissions),
                "permissions_resolved": sorted(
                    before_excess_permissions - after_excess_permissions
                ),
            },
            "conditional": {
                "roles_added": sorted(after_conditional_roles - before_conditional_roles),
                "roles_removed": sorted(before_conditional_roles - after_conditional_roles),
                "permissions_added": sorted(
                    after_conditional_permissions - before_conditional_permissions
                ),
                "permissions_removed": sorted(
                    before_conditional_permissions - after_conditional_permissions
                ),
            },
            "trust_boundary_crossings": _classify_permissions(
                added_permissions
                | (after_conditional_permissions - before_conditional_permissions)
            ),
            "unresolved": {
                "introduced": sorted(after_unresolved - before_unresolved),
                "resolved": sorted(before_unresolved - after_unresolved),
            },
            "before_status": before["status"] if before else "absent",
            "after_status": after["status"] if after else "absent",
        }
        item["regressed"] = bool(
            item["excess"]["roles_introduced"]
            or item["excess"]["permissions_introduced"]
            or item["conditional"]["roles_added"]
            or item["conditional"]["permissions_added"]
            or item["unresolved"]["introduced"]
        )
        item["improved"] = bool(
            item["excess"]["roles_resolved"]
            or item["excess"]["permissions_resolved"]
            or item["conditional"]["roles_removed"]
            or item["conditional"]["permissions_removed"]
            or item["unresolved"]["resolved"]
        )
        if (
            item["deployed"]["roles_added"]
            or item["deployed"]["roles_removed"]
            or item["deployed"]["permissions_added"]
            or item["deployed"]["permissions_removed"]
            or item["regressed"]
            or item["improved"]
        ):
            agents.append(item)

    return {
        "schema_version": DEPLOYMENT_AUTHORITY_DELTA_SCHEMA_VERSION,
        "runtime_effectiveness": "not_verified",
        "base": {
            "provider": base.provider,
            "evidence_source": base.source,
        },
        "head": {
            "provider": head.provider,
            "evidence_source": head.source,
        },
        "summary": {
            "changed_agents": len(agents),
            "regressed_agents": sum(bool(item["regressed"]) for item in agents),
            "improved_agents": sum(bool(item["improved"]) for item in agents),
            "introduced_excess_roles": sum(
                len(item["excess"]["roles_introduced"]) for item in agents
            ),
            "introduced_excess_permissions": sum(
                len(item["excess"]["permissions_introduced"]) for item in agents
            ),
            "introduced_conditional_roles": sum(
                len(item["conditional"]["roles_added"]) for item in agents
            ),
            "introduced_conditional_permissions": sum(
                len(item["conditional"]["permissions_added"]) for item in agents
            ),
        },
        "agents": agents,
    }
