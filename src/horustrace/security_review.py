"""Reviewer-oriented correlation of authority, trust-boundary, and policy deltas."""
from __future__ import annotations

from typing import Any

SECURITY_REVIEW_SCHEMA_VERSION = 1


def build_security_review(
    authority_delta: dict[str, Any],
    policy_delta: dict[str, Any],
) -> dict[str, Any]:
    """Correlate technical deltas into review-sized security impact records."""
    violations_by_relationship: dict[str, list[dict[str, Any]]] = {}
    for item in policy_delta.get("introduced_violations", []):
        relationship_id = item.get("authority_relationship_id")
        if relationship_id:
            violations_by_relationship.setdefault(relationship_id, []).append(item)

    items: list[dict[str, Any]] = []
    for expansion in authority_delta.get("expansions", []):
        relationship_id = expansion.get("relationship_id")
        crossings = expansion.get("trust_boundary_crossings") or []
        violations = violations_by_relationship.get(str(relationship_id), [])
        items.append(
            {
                "kind": "authority_change",
                "relationship_id": relationship_id,
                "agent": expansion.get("agent"),
                "target": expansion.get("target"),
                "source_context": expansion.get("source_context", "unknown"),
                "expansion_reasons": list(expansion.get("expansion_reasons") or []),
                "trust_boundary_crossings": crossings,
                "policy_violations": violations,
                "runtime_effectiveness": "not_verified",
            }
        )

    for weakening in policy_delta.get("contract_weakenings", []):
        items.append(
            {
                "kind": "policy_weakening",
                "relationship_id": None,
                "agent": weakening.get("agent"),
                "target": None,
                "source_context": "policy",
                "expansion_reasons": [],
                "trust_boundary_crossings": [],
                "policy_violations": [],
                "policy_weakening": weakening,
                "runtime_effectiveness": "not_verified",
            }
        )

    items.sort(
        key=lambda item: (
            str(item.get("agent") or ""),
            str(item.get("kind") or ""),
            str(item.get("relationship_id") or ""),
        )
    )
    return {
        "schema_version": SECURITY_REVIEW_SCHEMA_VERSION,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "items": len(items),
            "authority_changes": sum(item["kind"] == "authority_change" for item in items),
            "policy_weakenings": sum(item["kind"] == "policy_weakening" for item in items),
            "items_with_policy_violations": sum(
                bool(item.get("policy_violations")) for item in items
            ),
            "items_with_boundary_crossings": sum(
                bool(item.get("trust_boundary_crossings")) for item in items
            ),
        },
        "items": items,
    }
