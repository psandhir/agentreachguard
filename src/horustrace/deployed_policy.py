"""Evaluate deployed cloud authority against repository Authority Contract v1.

This complements the source-level Authority Contract evaluator. It uses only explicit
offline deployment evidence and keeps conditional IAM applicability unresolved.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from horustrace.deployed_authority import (
    DeployedAuthorityRelationship,
    deployed_authority_relationships,
)
from horustrace.deployment_evidence import DeploymentEvidenceBundle
from horustrace.heuristics import matches_any
from horustrace.models import Agent, AuthorityContract, Graph

DEPLOYED_POLICY_SCHEMA_VERSION = 1


def _stable_result_id(
    status: str,
    relationship_id: str,
    clause: str,
    reason: str,
) -> str:
    payload = json.dumps(
        {
            "status": status,
            "relationship_id": relationship_id,
            "clause": clause,
            "reason": reason,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"deployed-policy-v1:{digest}"


@dataclass(frozen=True, slots=True)
class DeployedPolicyResult:
    result_id: str
    status: str
    deployed_authority_relationship_id: str
    agent: str
    clause: str
    dimension: str
    reason: str
    expected: tuple[str, ...]
    observed: tuple[str, ...]
    conditional: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "result_id": self.result_id,
            "status": self.status,
            "deployed_authority_relationship_id": self.deployed_authority_relationship_id,
            "agent": self.agent,
            "clause": self.clause,
            "dimension": self.dimension,
            "reason": self.reason,
            "expected": list(self.expected),
            "observed": list(self.observed),
            "conditional": self.conditional,
            "runtime_effectiveness": "not_verified",
        }


def _result(
    relationship: DeployedAuthorityRelationship,
    *,
    status: str,
    clause: str,
    dimension: str,
    reason: str,
    expected: Iterable[str],
    observed: Iterable[str],
    conditional: bool = False,
) -> DeployedPolicyResult:
    return DeployedPolicyResult(
        result_id=_stable_result_id(
            status,
            relationship.relationship_id,
            clause,
            reason,
        ),
        status=status,
        deployed_authority_relationship_id=relationship.relationship_id,
        agent=relationship.agent,
        clause=clause,
        dimension=dimension,
        reason=reason,
        expected=tuple(sorted(set(expected))),
        observed=tuple(sorted(set(observed))),
        conditional=conditional,
    )


def _dimension_results(
    relationship: DeployedAuthorityRelationship,
    contract: AuthorityContract,
    *,
    dimension: str,
    observed: Iterable[str],
    conditional: bool = False,
) -> list[DeployedPolicyResult]:
    allowed = set(getattr(contract.allow, dimension))
    denied = set(getattr(contract.deny, dimension))
    if not allowed and not denied:
        return []

    values = sorted(set(observed))
    if not values:
        return []

    status = "unresolved" if conditional else "violation"
    prefix = "conditional_" if conditional else ""
    results: list[DeployedPolicyResult] = []

    denied_values = [value for value in values if matches_any(value, sorted(denied))]
    if denied_values:
        results.append(
            _result(
                relationship,
                status=status,
                clause=f"deny.{dimension}",
                dimension=dimension,
                reason=f"{prefix}denied_{dimension}_observed",
                expected=denied,
                observed=denied_values,
                conditional=conditional,
            )
        )

    if allowed:
        outside = [value for value in values if not matches_any(value, sorted(allowed))]
        if outside:
            results.append(
                _result(
                    relationship,
                    status=status,
                    clause=f"allow.{dimension}",
                    dimension=dimension,
                    reason=f"{prefix}{dimension}_outside_allowlist",
                    expected=allowed,
                    observed=outside,
                    conditional=conditional,
                )
            )
    return results


def _binding_roles(
    relationship: DeployedAuthorityRelationship,
) -> tuple[set[str], set[str]]:
    unconditional: set[str] = set()
    conditional: set[str] = set()
    for binding in relationship.bindings:
        role = binding.get("role")
        if not isinstance(role, str) or not role:
            continue
        if binding.get("condition") is None:
            unconditional.add(role)
        else:
            conditional.add(role)
    return unconditional, conditional


def _evaluate_relationship(
    relationship: DeployedAuthorityRelationship,
    agent: Agent,
) -> dict[str, Any]:
    contract = agent.policy.authority
    if contract is None:
        return {
            "deployed_authority_relationship_id": relationship.relationship_id,
            "agent": relationship.agent,
            "status": "not_configured",
            "results": [],
            "runtime_effectiveness": "not_verified",
        }

    constrained = any(
        (
            contract.allow.identities,
            contract.deny.identities,
            contract.allow.iam_roles,
            contract.deny.iam_roles,
            contract.allow.permissions,
            contract.deny.permissions,
        )
    )
    if not constrained:
        return {
            "deployed_authority_relationship_id": relationship.relationship_id,
            "agent": relationship.agent,
            "status": "not_constrained",
            "results": [],
            "runtime_effectiveness": "not_verified",
        }

    results: list[DeployedPolicyResult] = []
    results.extend(
        _dimension_results(
            relationship,
            contract,
            dimension="identities",
            observed=[relationship.identity],
        )
    )
    unconditional_roles, conditional_roles = _binding_roles(relationship)
    results.extend(
        _dimension_results(
            relationship,
            contract,
            dimension="iam_roles",
            observed=unconditional_roles,
        )
    )
    results.extend(
        _dimension_results(
            relationship,
            contract,
            dimension="iam_roles",
            observed=conditional_roles,
            conditional=True,
        )
    )
    results.extend(
        _dimension_results(
            relationship,
            contract,
            dimension="permissions",
            observed=relationship.permissions,
        )
    )
    results.extend(
        _dimension_results(
            relationship,
            contract,
            dimension="permissions",
            observed=relationship.conditional_permissions,
            conditional=True,
        )
    )

    if any(item.status == "violation" for item in results):
        status = "violation"
    elif any(item.status == "unresolved" for item in results) or relationship.unresolved:
        status = "unresolved"
    else:
        status = "compliant"
    return {
        "deployed_authority_relationship_id": relationship.relationship_id,
        "agent": relationship.agent,
        "status": status,
        "results": [item.as_dict() for item in results],
        "unresolved_authority": list(relationship.unresolved),
        "runtime_effectiveness": "not_verified",
    }


def deployed_policy_report(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
) -> dict[str, Any]:
    agents = {agent.name: agent for agent in graph.agents}
    relationships = deployed_authority_relationships(graph, bundle)
    evaluations = [
        _evaluate_relationship(item, agents[item.agent])
        for item in relationships
        if item.agent in agents
    ]
    statuses = ("compliant", "violation", "unresolved", "not_configured", "not_constrained")
    return {
        "schema_version": DEPLOYED_POLICY_SCHEMA_VERSION,
        "provider": bundle.provider,
        "evidence_source": bundle.source,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "relationships": len(evaluations),
            **{
                status: sum(item["status"] == status for item in evaluations)
                for status in statuses
            },
            "violation_results": sum(
                result["status"] == "violation"
                for item in evaluations
                for result in item["results"]
            ),
            "unresolved_results": sum(
                result["status"] == "unresolved"
                for item in evaluations
                for result in item["results"]
            ),
        },
        "relationships": evaluations,
    }
