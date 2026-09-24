"""Semantic effective-authority delta with Trust Boundary Classification v1."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from horustrace.effective_authority import (
    EffectiveAuthorityRelationship,
    effective_authority_report,
    effective_authority_relationships,
)
from horustrace.models import Graph
from horustrace.source_context import classify_source_context
from horustrace.trust_boundaries import (
    classify_boundary_crossings,
    classify_relationship,
)

AUTHORITY_DELTA_SCHEMA_VERSION = 2


def _relative_path(value: str, root: Path) -> str:
    path = Path(value)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _relative_locations(value: Any, root: Path) -> Any:
    if isinstance(value, list):
        return [_relative_locations(item, root) for item in value]
    if isinstance(value, tuple):
        return [_relative_locations(item, root) for item in value]
    if not isinstance(value, dict):
        return value

    result: dict[str, Any] = {}
    for key, item in value.items():
        if key == "location" and isinstance(item, dict):
            location = dict(item)
            path = location.get("path")
            if isinstance(path, str):
                location["path"] = _relative_path(path, root)
            result[key] = location
        else:
            result[key] = _relative_locations(item, root)
    return result


def _relationship_index(graph: Graph, root: Path) -> dict[str, dict[str, Any]]:
    report = effective_authority_report(graph)
    relationships = _relative_locations(report.get("relationships", []), root)
    return {
        item["relationship_id"]: item
        for item in relationships
    }


def _typed_relationship_index(
    graph: Graph,
) -> dict[str, EffectiveAuthorityRelationship]:
    return {
        relationship.relationship_id: relationship
        for relationship in effective_authority_relationships(graph)
    }


def _semantic_relationship(item: dict[str, Any]) -> dict[str, Any]:
    return {
        key: item.get(key)
        for key in (
            "agent",
            "target",
            "capabilities",
            "identity",
            "approval",
            "tool_scope",
            "resources",
            "destinations",
            "semantics",
            "resolution",
            "dimensions",
            "unresolved",
        )
    }


def _source_context(item: dict[str, Any]) -> str:
    location = item.get("location") or {}
    path = location.get("path")
    if not isinstance(path, str) or not path:
        return "unknown"
    return classify_source_context(Path(path))


def _set_delta(before: list[str] | None, after: list[str] | None) -> dict[str, list[str]]:
    left = set(before or [])
    right = set(after or [])
    return {
        "added": sorted(right - left),
        "removed": sorted(left - right),
    }


def _identity_delta(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if before == after:
        return None
    before_doc = before or {}
    after_doc = after or {}
    return {
        "before": before,
        "after": after,
        "roles": _set_delta(before_doc.get("roles"), after_doc.get("roles")),
        "permissions": _set_delta(
            before_doc.get("permissions"),
            after_doc.get("permissions"),
        ),
        "oauth_scopes": _set_delta(
            before_doc.get("oauth_scopes"),
            after_doc.get("oauth_scopes"),
        ),
    }


def _canonical_security_item(
    item: dict[str, Any],
    *,
    exclude: set[str] | None = None,
) -> str:
    excluded = exclude or {"location"}
    payload = {
        key: value
        for key, value in item.items()
        if key not in excluded
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _object_list_delta(
    before: list[dict[str, Any]] | None,
    after: list[dict[str, Any]] | None,
) -> dict[str, list[dict[str, Any]]]:
    left = {
        _canonical_security_item(item): item
        for item in before or []
    }
    right = {
        _canonical_security_item(item): item
        for item in after or []
    }
    return {
        "added": [right[key] for key in sorted(set(right) - set(left))],
        "removed": [left[key] for key in sorted(set(left) - set(right))],
    }


def _tool_scope_expanded(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> bool:
    if before == after:
        return False
    if before is None and after is not None:
        return False
    if before is not None and after is None:
        return True

    before = before or {}
    after = after or {}
    before_allowed = set(before.get("allowed") or [])
    after_allowed = set(after.get("allowed") or [])
    before_denied = set(before.get("denied") or [])
    after_denied = set(after.get("denied") or [])

    if after_allowed - before_allowed:
        return True
    if before_denied - after_denied:
        return True

    restrictive = {"explicit_allowlist", "filtered"}
    before_scope = before.get("scope")
    after_scope = after.get("scope")
    return before_scope in restrictive and after_scope not in restrictive


def _approval_weakened(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> bool:
    if before == after:
        return False
    before = before or {}
    after = after or {}
    if before.get("required") is True and after.get("required") is not True:
        return True
    if before.get("guardrails") is True and after.get("guardrails") is not True:
        return True
    return (
        before.get("inherited_control") is True
        and after.get("inherited_control") is not True
    )


def _boundary_classification(
    relationship: EffectiveAuthorityRelationship,
) -> dict[str, Any]:
    return classify_relationship(relationship).as_dict()


def _changed_relationship(
    before: dict[str, Any],
    after: dict[str, Any],
    before_relationship: EffectiveAuthorityRelationship,
    after_relationship: EffectiveAuthorityRelationship,
) -> dict[str, Any]:
    changed_dimensions = [
        key
        for key in (
            "capabilities",
            "identity",
            "approval",
            "tool_scope",
            "resources",
            "destinations",
            "semantics",
            "resolution",
            "dimensions",
            "unresolved",
        )
        if before.get(key) != after.get(key)
    ]
    capabilities = _set_delta(
        before.get("capabilities"),
        after.get("capabilities"),
    )
    identity = _identity_delta(before.get("identity"), after.get("identity"))
    resources = _object_list_delta(
        before.get("resources"),
        after.get("resources"),
    )
    destinations = _object_list_delta(
        before.get("destinations"),
        after.get("destinations"),
    )

    expansion_reasons: list[str] = []
    if capabilities["added"]:
        expansion_reasons.append("capabilities_added")
    if identity:
        if identity["roles"]["added"]:
            expansion_reasons.append("identity_roles_added")
        if identity["permissions"]["added"]:
            expansion_reasons.append("identity_permissions_added")
        if identity["oauth_scopes"]["added"]:
            expansion_reasons.append("identity_oauth_scopes_added")
        if before.get("identity") is None and after.get("identity") is not None:
            expansion_reasons.append("identity_attached")
        elif (
            before.get("identity")
            and after.get("identity")
            and before["identity"].get("name") != after["identity"].get("name")
        ):
            expansion_reasons.append("identity_changed")
    if _approval_weakened(before.get("approval"), after.get("approval")):
        expansion_reasons.append("approval_weakened")
    if _tool_scope_expanded(before.get("tool_scope"), after.get("tool_scope")):
        expansion_reasons.append("tool_scope_expanded")
    if resources["added"]:
        expansion_reasons.append("resources_added")
    if destinations["added"]:
        expansion_reasons.append("destinations_added")

    crossings = [
        crossing.as_dict()
        for crossing in classify_boundary_crossings(
            before_relationship,
            after_relationship,
        )
    ]

    return {
        "relationship_id": after["relationship_id"],
        "agent": after["agent"],
        "target": after["target"],
        "source_context": _source_context(after),
        "changed_dimensions": changed_dimensions,
        "capabilities": capabilities,
        "identity": identity,
        "approval": (
            {
                "before": before.get("approval"),
                "after": after.get("approval"),
            }
            if before.get("approval") != after.get("approval")
            else None
        ),
        "tool_scope": (
            {
                "before": before.get("tool_scope"),
                "after": after.get("tool_scope"),
            }
            if before.get("tool_scope") != after.get("tool_scope")
            else None
        ),
        "resources": resources,
        "destinations": destinations,
        "resolution": {
            "before": before.get("resolution"),
            "after": after.get("resolution"),
        },
        "expansion_reasons": expansion_reasons,
        "trust_boundaries": {
            "before": _boundary_classification(before_relationship),
            "after": _boundary_classification(after_relationship),
        },
        "trust_boundary_crossings": crossings,
        "before": before,
        "after": after,
    }


def _crossing_summary(
    changed: list[dict[str, Any]],
) -> dict[str, Any]:
    crossings = [
        crossing
        for item in changed
        for crossing in item.get("trust_boundary_crossings", [])
    ]
    expanded_by_family = Counter(
        crossing["family"]
        for crossing in crossings
        if crossing["direction"] == "expanded"
    )
    weakened_by_family = Counter(
        crossing["family"]
        for crossing in crossings
        if crossing["direction"] == "weakened"
    )
    return {
        "trust_boundary_crossings": len(crossings),
        "expanded_or_weakened_boundary_crossings": sum(
            crossing["direction"] in {"expanded", "weakened"}
            for crossing in crossings
        ),
        "expanded_boundary_crossings_by_family": dict(
            sorted(expanded_by_family.items())
        ),
        "weakened_boundary_crossings_by_family": dict(
            sorted(weakened_by_family.items())
        ),
    }


def compare_effective_authority(
    base_graph: Graph,
    base_root: Path,
    head_graph: Graph,
    head_root: Path,
) -> dict[str, Any]:
    """Compare stable effective-authority relationships across two scans."""
    base = _relationship_index(base_graph, base_root)
    head = _relationship_index(head_graph, head_root)
    base_typed = _typed_relationship_index(base_graph)
    head_typed = _typed_relationship_index(head_graph)

    added_ids = sorted(set(head) - set(base))
    removed_ids = sorted(set(base) - set(head))
    common_ids = sorted(set(base) & set(head))

    added = [
        {
            **head[item],
            "source_context": _source_context(head[item]),
            "expansion_reasons": ["new_relationship"],
            "trust_boundaries": _boundary_classification(head_typed[item]),
        }
        for item in added_ids
    ]
    removed = [
        {
            **base[item],
            "source_context": _source_context(base[item]),
            "trust_boundaries": _boundary_classification(base_typed[item]),
        }
        for item in removed_ids
    ]
    changed = [
        _changed_relationship(
            base[item],
            head[item],
            base_typed[item],
            head_typed[item],
        )
        for item in common_ids
        if _semantic_relationship(base[item]) != _semantic_relationship(head[item])
    ]
    expansions = [
        *added,
        *[
            item
            for item in changed
            if item["expansion_reasons"]
        ],
    ]
    crossing_summary = _crossing_summary(changed)

    return {
        "schema_version": AUTHORITY_DELTA_SCHEMA_VERSION,
        "summary": {
            "added_relationships": len(added),
            "removed_relationships": len(removed),
            "changed_relationships": len(changed),
            "expanded_relationships": len(expansions),
            **crossing_summary,
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "expansions": expansions,
    }
