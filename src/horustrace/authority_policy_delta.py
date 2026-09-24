"""Change-aware Authority Contract evaluation for HorusTrace v0.6."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from horustrace.authority_contract import authority_contract_report
from horustrace.models import Graph
from horustrace.source_context import classify_source_context

AUTHORITY_POLICY_DELTA_SCHEMA_VERSION = 1


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

    result = {
        key: _relative_locations(item, root)
        for key, item in value.items()
    }
    path = result.get("path")
    if (
        isinstance(path, str)
        and ("line" in result or "column" in result)
    ):
        result["path"] = _relative_path(path, root)
    return result


def _relative_result(record: dict[str, Any], root: Path) -> dict[str, Any]:
    result = _relative_locations(record, root)
    relationship_location = result.get("relationship_location") or {}
    path = relationship_location.get("path")
    result["source_context"] = (
        classify_source_context(Path(path))
        if isinstance(path, str) and path
        else "unknown"
    )
    return result


def _result_index(
    records: list[dict[str, Any]],
    root: Path,
) -> dict[str, dict[str, Any]]:
    return {
        record["result_id"]: _relative_result(record, root)
        for record in records
    }


def _authority_context(
    authority_delta: dict[str, Any],
    *,
    side: str,
) -> dict[str, dict[str, Any]]:
    context: dict[str, dict[str, Any]] = {}
    edge_key = "added" if side == "after" else "removed"
    for item in authority_delta.get(edge_key, []):
        relationship_id = item.get("relationship_id")
        if relationship_id:
            context[relationship_id] = {
                "trust_boundaries": item.get("trust_boundaries"),
                "trust_boundary_crossings": [],
            }
    for item in authority_delta.get("changed", []):
        relationship_id = item.get("relationship_id")
        if relationship_id:
            trust_boundaries = item.get("trust_boundaries") or {}
            context[relationship_id] = {
                "trust_boundaries": trust_boundaries.get(side),
                "trust_boundary_crossings": list(
                    item.get("trust_boundary_crossings") or []
                ),
            }
    return context


def _with_authority_context(
    record: dict[str, Any],
    context: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    authority = context.get(record["authority_relationship_id"], {})
    return {
        **record,
        "trust_boundaries": authority.get("trust_boundaries"),
        "trust_boundary_crossings": authority.get(
            "trust_boundary_crossings",
            [],
        ),
    }


def compare_authority_contracts(
    base_graph: Graph,
    base_root: Path,
    head_graph: Graph,
    head_root: Path,
    authority_delta: dict[str, Any],
) -> dict[str, Any]:
    """Compare stable contract violation/unresolved results across two scans."""
    base_report = authority_contract_report(base_graph)
    head_report = authority_contract_report(head_graph)

    base_violations = _result_index(base_report["violations"], base_root)
    head_violations = _result_index(head_report["violations"], head_root)
    base_unresolved = _result_index(base_report["unresolved"], base_root)
    head_unresolved = _result_index(head_report["unresolved"], head_root)

    introduced_violation_ids = sorted(set(head_violations) - set(base_violations))
    resolved_violation_ids = sorted(set(base_violations) - set(head_violations))
    introduced_unresolved_ids = sorted(set(head_unresolved) - set(base_unresolved))
    resolved_unresolved_ids = sorted(set(base_unresolved) - set(head_unresolved))

    head_authority_context = _authority_context(authority_delta, side="after")
    base_authority_context = _authority_context(authority_delta, side="before")
    introduced_violations = [
        _with_authority_context(head_violations[item], head_authority_context)
        for item in introduced_violation_ids
    ]
    resolved_violations = [
        _with_authority_context(base_violations[item], base_authority_context)
        for item in resolved_violation_ids
    ]
    introduced_unresolved = [
        _with_authority_context(head_unresolved[item], head_authority_context)
        for item in introduced_unresolved_ids
    ]
    resolved_unresolved = [
        _with_authority_context(base_unresolved[item], base_authority_context)
        for item in resolved_unresolved_ids
    ]

    return {
        "schema_version": AUTHORITY_POLICY_DELTA_SCHEMA_VERSION,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "base_violations": len(base_violations),
            "head_violations": len(head_violations),
            "introduced_violations": len(introduced_violations),
            "resolved_violations": len(resolved_violations),
            "base_unresolved": len(base_unresolved),
            "head_unresolved": len(head_unresolved),
            "introduced_unresolved": len(introduced_unresolved),
            "resolved_unresolved": len(resolved_unresolved),
        },
        "introduced_violations": introduced_violations,
        "resolved_violations": resolved_violations,
        "introduced_unresolved": introduced_unresolved,
        "resolved_unresolved": resolved_unresolved,
    }
