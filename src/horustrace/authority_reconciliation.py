"""Reconcile source-observed authority with deployed cloud authority.

The reconciler is deliberately evidence-sensitive. It only labels authority as excess
or missing for dimensions where HorusTrace has an explicit required baseline. Unknown
required authority remains unresolved rather than being interpreted as least privilege.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from horustrace.deployed_authority import (
    DeployedAuthorityRelationship,
    deployed_authority_relationships,
)
from horustrace.deployment_evidence import DeploymentEvidenceBundle
from horustrace.effective_authority import (
    EffectiveAuthorityRelationship,
    effective_authority_relationships,
)
from horustrace.models import Graph

AUTHORITY_RECONCILIATION_SCHEMA_VERSION = 1


def _stable_id(agent: str) -> str:
    digest = hashlib.sha256(agent.encode("utf-8")).hexdigest()[:20]
    return f"authority-reconciliation-v1:{digest}"


def _required_authority(
    relationships: list[EffectiveAuthorityRelationship],
) -> tuple[set[str], set[str], set[str]]:
    roles: set[str] = set()
    permissions: set[str] = set()
    unresolved: set[str] = set()
    if not relationships:
        unresolved.update({"required_roles", "required_permissions"})
        return roles, permissions, unresolved

    identity_relationships = [item for item in relationships if item.identity is not None]
    if not identity_relationships:
        unresolved.update({"required_roles", "required_permissions"})
        return roles, permissions, unresolved

    for relationship in identity_relationships:
        identity = relationship.identity or {}
        roles.update(str(value) for value in identity.get("roles") or [] if value)
        permissions.update(
            str(value) for value in identity.get("permissions") or [] if value
        )
        if relationship.dimensions.get("identity") == "unknown":
            unresolved.add("required_identity")

    if not roles:
        unresolved.add("required_roles")
    if not permissions:
        unresolved.add("required_permissions")
    return roles, permissions, unresolved


def _deployed_authority(
    relationships: list[DeployedAuthorityRelationship],
) -> tuple[set[str], set[str], set[str], set[str], set[str]]:
    roles: set[str] = set()
    conditional_roles: set[str] = set()
    permissions: set[str] = set()
    conditional_permissions: set[str] = set()
    unresolved: set[str] = set()
    if not relationships:
        unresolved.add("deployed_identity")
        return roles, conditional_roles, permissions, conditional_permissions, unresolved
    for relationship in relationships:
        roles.update(relationship.roles)
        conditional_roles.update(relationship.conditional_roles)
        permissions.update(relationship.permissions)
        conditional_permissions.update(relationship.conditional_permissions)
        unresolved.update(relationship.unresolved)
    return roles, conditional_roles, permissions, conditional_permissions, unresolved


def _status(
    *,
    excess_roles: set[str],
    excess_permissions: set[str],
    missing_roles: set[str],
    missing_permissions: set[str],
    unresolved: set[str],
) -> str:
    excess = bool(excess_roles or excess_permissions)
    missing = bool(missing_roles or missing_permissions)
    if excess and missing:
        return "mixed"
    if excess:
        return "excess_authority"
    if missing:
        return "missing_authority"
    if unresolved:
        return "unresolved"
    return "aligned"


@dataclass(frozen=True, slots=True)
class AgentAuthorityReconciliation:
    reconciliation_id: str
    agent: str
    required_roles: tuple[str, ...]
    required_permissions: tuple[str, ...]
    deployed_roles: tuple[str, ...]
    conditional_roles: tuple[str, ...]
    deployed_permissions: tuple[str, ...]
    conditional_permissions: tuple[str, ...]
    excess_roles: tuple[str, ...]
    excess_permissions: tuple[str, ...]
    missing_roles: tuple[str, ...]
    missing_permissions: tuple[str, ...]
    unresolved: tuple[str, ...]
    status: str
    effective_authority_relationship_ids: tuple[str, ...]
    deployed_authority_relationship_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "reconciliation_id": self.reconciliation_id,
            "agent": self.agent,
            "required": {
                "roles": list(self.required_roles),
                "permissions": list(self.required_permissions),
            },
            "deployed": {
                "roles": list(self.deployed_roles),
                "conditional_roles": list(self.conditional_roles),
                "permissions": list(self.deployed_permissions),
                "conditional_permissions": list(self.conditional_permissions),
            },
            "excess": {
                "roles": list(self.excess_roles),
                "permissions": list(self.excess_permissions),
            },
            "missing": {
                "roles": list(self.missing_roles),
                "permissions": list(self.missing_permissions),
            },
            "unresolved": list(self.unresolved),
            "status": self.status,
            "evidence": {
                "effective_authority_relationship_ids": list(
                    self.effective_authority_relationship_ids
                ),
                "deployed_authority_relationship_ids": list(
                    self.deployed_authority_relationship_ids
                ),
            },
            "runtime_effectiveness": "not_verified",
        }


def authority_reconciliations(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
) -> list[AgentAuthorityReconciliation]:
    effective = effective_authority_relationships(graph)
    deployed = deployed_authority_relationships(graph, bundle)
    effective_by_agent: dict[str, list[EffectiveAuthorityRelationship]] = {}
    deployed_by_agent: dict[str, list[DeployedAuthorityRelationship]] = {}
    for item in effective:
        effective_by_agent.setdefault(item.agent, []).append(item)
    for item in deployed:
        deployed_by_agent.setdefault(item.agent, []).append(item)

    result: list[AgentAuthorityReconciliation] = []
    for agent in sorted({item.name for item in graph.agents}):
        effective_items = effective_by_agent.get(agent, [])
        deployed_items = deployed_by_agent.get(agent, [])
        required_roles, required_permissions, required_unresolved = _required_authority(
            effective_items
        )
        (
            deployed_roles,
            conditional_roles,
            deployed_permissions,
            conditional_permissions,
            deployed_unresolved,
        ) = _deployed_authority(deployed_items)
        unresolved = set(required_unresolved) | set(deployed_unresolved)

        excess_roles = (
            deployed_roles - required_roles
            if "required_roles" not in required_unresolved
            else set()
        )
        missing_roles = (
            required_roles - deployed_roles
            if "required_roles" not in required_unresolved
            else set()
        )
        excess_permissions = (
            deployed_permissions - required_permissions
            if "required_permissions" not in required_unresolved
            else set()
        )
        missing_permissions = (
            required_permissions - deployed_permissions
            if "required_permissions" not in required_unresolved
            else set()
        )
        if conditional_roles or conditional_permissions:
            unresolved.add("conditional_authority")

        result.append(
            AgentAuthorityReconciliation(
                reconciliation_id=_stable_id(agent),
                agent=agent,
                required_roles=tuple(sorted(required_roles)),
                required_permissions=tuple(sorted(required_permissions)),
                deployed_roles=tuple(sorted(deployed_roles)),
                conditional_roles=tuple(sorted(conditional_roles)),
                deployed_permissions=tuple(sorted(deployed_permissions)),
                conditional_permissions=tuple(sorted(conditional_permissions)),
                excess_roles=tuple(sorted(excess_roles)),
                excess_permissions=tuple(sorted(excess_permissions)),
                missing_roles=tuple(sorted(missing_roles)),
                missing_permissions=tuple(sorted(missing_permissions)),
                unresolved=tuple(sorted(unresolved)),
                status=_status(
                    excess_roles=excess_roles,
                    excess_permissions=excess_permissions,
                    missing_roles=missing_roles,
                    missing_permissions=missing_permissions,
                    unresolved=unresolved,
                ),
                effective_authority_relationship_ids=tuple(
                    sorted(item.relationship_id for item in effective_items)
                ),
                deployed_authority_relationship_ids=tuple(
                    sorted(item.relationship_id for item in deployed_items)
                ),
            )
        )
    return result


def authority_reconciliation_report(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
) -> dict[str, Any]:
    reconciliations = authority_reconciliations(graph, bundle)
    statuses = ("aligned", "excess_authority", "missing_authority", "mixed", "unresolved")
    return {
        "schema_version": AUTHORITY_RECONCILIATION_SCHEMA_VERSION,
        "provider": bundle.provider,
        "evidence_source": bundle.source,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "agents": len(reconciliations),
            **{
                status: sum(item.status == status for item in reconciliations)
                for status in statuses
            },
            "excess_roles": sum(len(item.excess_roles) for item in reconciliations),
            "excess_permissions": sum(
                len(item.excess_permissions) for item in reconciliations
            ),
            "missing_roles": sum(len(item.missing_roles) for item in reconciliations),
            "missing_permissions": sum(
                len(item.missing_permissions) for item in reconciliations
            ),
        },
        "agents": [item.as_dict() for item in reconciliations],
    }
