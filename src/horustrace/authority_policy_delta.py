"""Change-aware Authority Contract evaluation for HorusTrace v0.6."""
from __future__ import annotations

import fnmatch
import hashlib
import json
from pathlib import Path
from typing import Any

from horustrace.authority_contract import authority_contract_report
from horustrace.models import AuthorityContract, Graph, MCPToolContract, SourceLocation
from horustrace.source_context import classify_source_context

AUTHORITY_POLICY_DELTA_SCHEMA_VERSION = 2

_SCOPE_DIMENSIONS = (
    "capabilities",
    "identities",
    "resources",
    "destinations",
    "iam_roles",
    "permissions",
    "oauth_scopes",
    "mcp_servers",
)


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


def _location(
    contract: AuthorityContract | None,
    clause: str,
    root: Path,
) -> dict[str, Any] | None:
    if contract is None:
        return None
    location: SourceLocation | None = (
        contract.clause_locations.get(clause) or contract.location
    )
    if location is None:
        return None
    return {
        "path": _relative_path(str(location.path), root),
        "line": location.line,
        "column": location.column,
    }


def _change_id(
    *,
    agent: str,
    clause: str,
    change: str,
    direction: str,
) -> str:
    # Contract values and source locations are intentionally excluded. Policy
    # destinations can contain sensitive URL material, and checkout paths must
    # not affect stable identity.
    payload = json.dumps(
        {
            "agent": agent,
            "clause": clause,
            "change": change,
            "direction": direction,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"contract-delta-v1:{digest}"


def _contract_nonempty(contract: AuthorityContract | None) -> bool:
    if contract is None:
        return False
    if contract.require_approval_for or contract.mcp_tools:
        return True
    return any(
        getattr(contract.allow, dimension) or getattr(contract.deny, dimension)
        for dimension in _SCOPE_DIMENSIONS
    )


def _pattern_covered(pattern: str, covering_patterns: set[str]) -> bool:
    return any(fnmatch.fnmatch(pattern, candidate) for candidate in covering_patterns)


def _uncovered_patterns(
    candidates: set[str],
    covering_patterns: set[str],
) -> set[str]:
    return {
        value
        for value in candidates
        if not _pattern_covered(value, covering_patterns)
    }


def _contract_change(
    *,
    agent: str,
    clause: str,
    change: str,
    direction: str,
    before: set[str] | list[str],
    after: set[str] | list[str],
    base_contract: AuthorityContract | None,
    head_contract: AuthorityContract | None,
    base_root: Path,
    head_root: Path,
    location_side: str,
) -> dict[str, Any]:
    before_location = _location(base_contract, clause, base_root)
    after_location = _location(head_contract, clause, head_root)
    contract_location = (
        after_location if location_side == "after" else before_location
    )
    return {
        "change_id": _change_id(
            agent=agent,
            clause=clause,
            change=change,
            direction=direction,
        ),
        "agent": agent,
        "clause": clause,
        "change": change,
        "direction": direction,
        "before": sorted(before),
        "after": sorted(after),
        "contract_location": contract_location,
        "before_location": before_location,
        "after_location": after_location,
    }


def _scope_changes(
    *,
    agent: str,
    mode: str,
    base_contract: AuthorityContract,
    head_contract: AuthorityContract,
    base_root: Path,
    head_root: Path,
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    base_scope = getattr(base_contract, mode)
    head_scope = getattr(head_contract, mode)

    for dimension in _SCOPE_DIMENSIONS:
        clause = f"{mode}.{dimension}"
        before = set(getattr(base_scope, dimension))
        after = set(getattr(head_scope, dimension))
        if before == after:
            continue

        if mode == "allow":
            if before and not after:
                changes.append(
                    _contract_change(
                        agent=agent,
                        clause=clause,
                        change="constraint_removed",
                        direction="weakened",
                        before=before,
                        after=after,
                        base_contract=base_contract,
                        head_contract=head_contract,
                        base_root=base_root,
                        head_root=head_root,
                        location_side="before",
                    )
                )
                continue
            if not before and after:
                changes.append(
                    _contract_change(
                        agent=agent,
                        clause=clause,
                        change="constraint_added",
                        direction="strengthened",
                        before=before,
                        after=after,
                        base_contract=base_contract,
                        head_contract=head_contract,
                        base_root=base_root,
                        head_root=head_root,
                        location_side="after",
                    )
                )
                continue

            widened = _uncovered_patterns(after, before)
            narrowed = _uncovered_patterns(before, after)
            if widened:
                changes.append(
                    _contract_change(
                        agent=agent,
                        clause=clause,
                        change="allowlist_widened",
                        direction="weakened",
                        before=before,
                        after=after,
                        base_contract=base_contract,
                        head_contract=head_contract,
                        base_root=base_root,
                        head_root=head_root,
                        location_side="after",
                    )
                )
            if narrowed:
                changes.append(
                    _contract_change(
                        agent=agent,
                        clause=clause,
                        change="allowlist_narrowed",
                        direction="strengthened",
                        before=before,
                        after=after,
                        base_contract=base_contract,
                        head_contract=head_contract,
                        base_root=base_root,
                        head_root=head_root,
                        location_side="after",
                    )
                )
        else:
            removed = _uncovered_patterns(before, after)
            added = _uncovered_patterns(after, before)
            if removed:
                changes.append(
                    _contract_change(
                        agent=agent,
                        clause=clause,
                        change="deny_constraint_removed",
                        direction="weakened",
                        before=before,
                        after=after,
                        base_contract=base_contract,
                        head_contract=head_contract,
                        base_root=base_root,
                        head_root=head_root,
                        location_side="before",
                    )
                )
            if added:
                changes.append(
                    _contract_change(
                        agent=agent,
                        clause=clause,
                        change="deny_constraint_added",
                        direction="strengthened",
                        before=before,
                        after=after,
                        base_contract=base_contract,
                        head_contract=head_contract,
                        base_root=base_root,
                        head_root=head_root,
                        location_side="after",
                    )
                )
    return changes


def _approval_changes(
    *,
    agent: str,
    base_contract: AuthorityContract,
    head_contract: AuthorityContract,
    base_root: Path,
    head_root: Path,
) -> list[dict[str, Any]]:
    before = set(base_contract.require_approval_for)
    after = set(head_contract.require_approval_for)
    changes: list[dict[str, Any]] = []
    if before - after:
        changes.append(
            _contract_change(
                agent=agent,
                clause="require_approval_for",
                change="approval_requirement_removed",
                direction="weakened",
                before=before,
                after=after,
                base_contract=base_contract,
                head_contract=head_contract,
                base_root=base_root,
                head_root=head_root,
                location_side="before",
            )
        )
    if after - before:
        changes.append(
            _contract_change(
                agent=agent,
                clause="require_approval_for",
                change="approval_requirement_added",
                direction="strengthened",
                before=before,
                after=after,
                base_contract=base_contract,
                head_contract=head_contract,
                base_root=base_root,
                head_root=head_root,
                location_side="after",
            )
        )
    return changes


def _mcp_map(contract: AuthorityContract) -> dict[str, MCPToolContract]:
    return {item.server: item for item in contract.mcp_tools}


def _mcp_tool_changes(
    *,
    agent: str,
    base_contract: AuthorityContract,
    head_contract: AuthorityContract,
    base_root: Path,
    head_root: Path,
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    base = _mcp_map(base_contract)
    head = _mcp_map(head_contract)

    for server in sorted(set(base) | set(head)):
        before_policy = base.get(server)
        after_policy = head.get(server)
        before_allow = set(before_policy.allowed_tools) if before_policy else set()
        after_allow = set(after_policy.allowed_tools) if after_policy else set()
        before_deny = set(before_policy.denied_tools) if before_policy else set()
        after_deny = set(after_policy.denied_tools) if after_policy else set()

        allow_clause = f"mcp_tools.{server}.allow"
        if before_allow != after_allow:
            if before_allow and not after_allow:
                changes.append(
                    _contract_change(
                        agent=agent,
                        clause=allow_clause,
                        change="mcp_allowlist_removed",
                        direction="weakened",
                        before=before_allow,
                        after=after_allow,
                        base_contract=base_contract,
                        head_contract=head_contract,
                        base_root=base_root,
                        head_root=head_root,
                        location_side="before",
                    )
                )
            elif not before_allow and after_allow:
                changes.append(
                    _contract_change(
                        agent=agent,
                        clause=allow_clause,
                        change="mcp_allowlist_added",
                        direction="strengthened",
                        before=before_allow,
                        after=after_allow,
                        base_contract=base_contract,
                        head_contract=head_contract,
                        base_root=base_root,
                        head_root=head_root,
                        location_side="after",
                    )
                )
            else:
                if after_allow - before_allow:
                    changes.append(
                        _contract_change(
                            agent=agent,
                            clause=allow_clause,
                            change="mcp_allowlist_widened",
                            direction="weakened",
                            before=before_allow,
                            after=after_allow,
                            base_contract=base_contract,
                            head_contract=head_contract,
                            base_root=base_root,
                            head_root=head_root,
                            location_side="after",
                        )
                    )
                if before_allow - after_allow:
                    changes.append(
                        _contract_change(
                            agent=agent,
                            clause=allow_clause,
                            change="mcp_allowlist_narrowed",
                            direction="strengthened",
                            before=before_allow,
                            after=after_allow,
                            base_contract=base_contract,
                            head_contract=head_contract,
                            base_root=base_root,
                            head_root=head_root,
                            location_side="after",
                        )
                    )

        deny_clause = f"mcp_tools.{server}.deny"
        if before_deny - after_deny:
            changes.append(
                _contract_change(
                    agent=agent,
                    clause=deny_clause,
                    change="mcp_deny_removed",
                    direction="weakened",
                    before=before_deny,
                    after=after_deny,
                    base_contract=base_contract,
                    head_contract=head_contract,
                    base_root=base_root,
                    head_root=head_root,
                    location_side="before",
                )
            )
        if after_deny - before_deny:
            changes.append(
                _contract_change(
                    agent=agent,
                    clause=deny_clause,
                    change="mcp_deny_added",
                    direction="strengthened",
                    before=before_deny,
                    after=after_deny,
                    base_contract=base_contract,
                    head_contract=head_contract,
                    base_root=base_root,
                    head_root=head_root,
                    location_side="after",
                )
            )

    return changes


def compare_contract_constraints(
    base_graph: Graph,
    base_root: Path,
    head_graph: Graph,
    head_root: Path,
) -> dict[str, Any]:
    """Compare Authority Contract posture for agents present on both sides."""
    base_agents = {agent.name: agent for agent in base_graph.agents}
    head_agents = {agent.name: agent for agent in head_graph.agents}
    changes: list[dict[str, Any]] = []

    for agent_name in sorted(set(base_agents) & set(head_agents)):
        base_contract = base_agents[agent_name].policy.authority
        head_contract = head_agents[agent_name].policy.authority

        if not _contract_nonempty(base_contract) and not _contract_nonempty(head_contract):
            continue
        if _contract_nonempty(base_contract) and not _contract_nonempty(head_contract):
            changes.append(
                _contract_change(
                    agent=agent_name,
                    clause="authority",
                    change="contract_removed",
                    direction="weakened",
                    before=["contract_present"],
                    after=[],
                    base_contract=base_contract,
                    head_contract=head_contract,
                    base_root=base_root,
                    head_root=head_root,
                    location_side="before",
                )
            )
            continue
        if not _contract_nonempty(base_contract) and _contract_nonempty(head_contract):
            changes.append(
                _contract_change(
                    agent=agent_name,
                    clause="authority",
                    change="contract_added",
                    direction="strengthened",
                    before=[],
                    after=["contract_present"],
                    base_contract=base_contract,
                    head_contract=head_contract,
                    base_root=base_root,
                    head_root=head_root,
                    location_side="after",
                )
            )
            continue

        assert base_contract is not None
        assert head_contract is not None
        changes.extend(
            _scope_changes(
                agent=agent_name,
                mode="allow",
                base_contract=base_contract,
                head_contract=head_contract,
                base_root=base_root,
                head_root=head_root,
            )
        )
        changes.extend(
            _scope_changes(
                agent=agent_name,
                mode="deny",
                base_contract=base_contract,
                head_contract=head_contract,
                base_root=base_root,
                head_root=head_root,
            )
        )
        changes.extend(
            _approval_changes(
                agent=agent_name,
                base_contract=base_contract,
                head_contract=head_contract,
                base_root=base_root,
                head_root=head_root,
            )
        )
        changes.extend(
            _mcp_tool_changes(
                agent=agent_name,
                base_contract=base_contract,
                head_contract=head_contract,
                base_root=base_root,
                head_root=head_root,
            )
        )

    changes = sorted(
        changes,
        key=lambda item: (
            item["agent"],
            item["clause"],
            item["direction"],
            item["change"],
            item["change_id"],
        ),
    )
    weakenings = [item for item in changes if item["direction"] == "weakened"]
    strengthenings = [
        item for item in changes if item["direction"] == "strengthened"
    ]
    return {
        "schema_version": 1,
        "summary": {
            "changes": len(changes),
            "weakenings": len(weakenings),
            "strengthenings": len(strengthenings),
        },
        "changes": changes,
        "weakenings": weakenings,
        "strengthenings": strengthenings,
    }


def compare_authority_contracts(
    base_graph: Graph,
    base_root: Path,
    head_graph: Graph,
    head_root: Path,
    authority_delta: dict[str, Any],
) -> dict[str, Any]:
    """Compare contract posture plus stable violation/unresolved results."""
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
    contract_delta = compare_contract_constraints(
        base_graph,
        base_root,
        head_graph,
        head_root,
    )

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
            "contract_changes": contract_delta["summary"]["changes"],
            "contract_weakenings": contract_delta["summary"]["weakenings"],
            "contract_strengthenings": contract_delta["summary"]["strengthenings"],
        },
        "introduced_violations": introduced_violations,
        "resolved_violations": resolved_violations,
        "introduced_unresolved": introduced_unresolved,
        "resolved_unresolved": resolved_unresolved,
        "contract_delta": contract_delta,
        "contract_weakenings": contract_delta["weakenings"],
        "contract_strengthenings": contract_delta["strengthenings"],
    }
