"""Change-aware comparison of HorusTrace findings and authority graphs."""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from horustrace.config import load_config
from horustrace.git_snapshot import GitSnapshot, materialize_git_ref
from horustrace.models import Finding, Graph, Severity
from horustrace.scanner import scan
from horustrace.suppressions import fingerprint

_MAX_CONSOLE_ITEMS = 40


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _finding_record(finding: Finding, root: Path) -> dict[str, Any]:
    value = finding.fingerprint or fingerprint(finding, root)
    location = None
    if finding.location is not None:
        location = {
            "path": _relative_path(finding.location.path, root),
            "line": finding.location.line,
            "column": finding.location.column,
        }
    return {
        "fingerprint": value,
        "rule_id": finding.rule_id,
        "severity": finding.severity.label(),
        "title": finding.title,
        "agent": finding.agent,
        "assessment": finding.assessment,
        "confidence": finding.confidence.value if finding.confidence else None,
        "source_context": finding.source_context,
        "location": location,
        "evidence": list(finding.evidence),
    }


def _finding_index(findings: list[Finding], root: Path) -> dict[str, dict[str, Any]]:
    return {
        record["fingerprint"]: record
        for finding in findings
        if (record := _finding_record(finding, root))
    }


def _finding_semantics(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: record.get(key)
        for key in (
            "rule_id",
            "severity",
            "agent",
            "assessment",
            "confidence",
            "source_context",
            "evidence",
        )
    }


def _semantic_node(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": node.get("kind"),
        "name": node.get("name"),
        "framework": node.get("framework"),
        "attributes": node.get("attributes") or {},
    }


def _changed_node_record(
    before: dict[str, Any],
    after: dict[str, Any],
) -> dict[str, Any]:
    before_attributes = before.get("attributes") or {}
    after_attributes = after.get("attributes") or {}
    before_capabilities = set(before_attributes.get("capabilities") or [])
    after_capabilities = set(after_attributes.get("capabilities") or [])
    changed_attribute_keys = sorted(
        key
        for key in set(before_attributes) | set(after_attributes)
        if before_attributes.get(key) != after_attributes.get(key)
    )
    return {
        "id": after["id"],
        "kind": after.get("kind"),
        "name": after.get("name"),
        "framework": after.get("framework"),
        "changed_attributes": changed_attribute_keys,
        "added_capabilities": sorted(after_capabilities - before_capabilities),
        "removed_capabilities": sorted(before_capabilities - after_capabilities),
        "before": _semantic_node(before),
        "after": _semantic_node(after),
    }


def _edge_record(
    edge: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    source = nodes.get(edge.get("source"), {})
    target = nodes.get(edge.get("target"), {})
    return {
        **edge,
        "source_name": source.get("name"),
        "source_kind": source.get("kind"),
        "target_name": target.get("name"),
        "target_kind": target.get("kind"),
    }


def compare_scans(
    base_graph: Graph,
    base_findings: list[Finding],
    base_root: Path,
    head_graph: Graph,
    head_findings: list[Finding],
    head_root: Path,
    *,
    base_ref: str,
    head_ref: str,
    base_commit: str | None = None,
    head_commit: str | None = None,
    base_skipped_entries: int = 0,
    head_skipped_entries: int = 0,
) -> dict[str, Any]:
    """Return a deterministic security delta between two completed scans."""
    base_finding_index = _finding_index(base_findings, base_root)
    head_finding_index = _finding_index(head_findings, head_root)

    base_fingerprints = set(base_finding_index)
    head_fingerprints = set(head_finding_index)
    introduced_ids = sorted(head_fingerprints - base_fingerprints)
    resolved_ids = sorted(base_fingerprints - head_fingerprints)
    common_ids = sorted(base_fingerprints & head_fingerprints)

    introduced = [head_finding_index[item] for item in introduced_ids]
    resolved = [base_finding_index[item] for item in resolved_ids]
    changed_findings = [
        {
            "fingerprint": item,
            "before": base_finding_index[item],
            "after": head_finding_index[item],
        }
        for item in common_ids
        if _finding_semantics(base_finding_index[item])
        != _finding_semantics(head_finding_index[item])
    ]

    base_adg = base_graph.adg.as_dict() if base_graph.adg else {"nodes": [], "edges": []}
    head_adg = head_graph.adg.as_dict() if head_graph.adg else {"nodes": [], "edges": []}
    base_nodes = {item["id"]: item for item in base_adg.get("nodes", [])}
    head_nodes = {item["id"]: item for item in head_adg.get("nodes", [])}
    base_edges = {item["id"]: item for item in base_adg.get("edges", [])}
    head_edges = {item["id"]: item for item in head_adg.get("edges", [])}

    added_node_ids = sorted(set(head_nodes) - set(base_nodes))
    removed_node_ids = sorted(set(base_nodes) - set(head_nodes))
    common_node_ids = sorted(set(base_nodes) & set(head_nodes))
    changed_nodes = [
        _changed_node_record(base_nodes[item], head_nodes[item])
        for item in common_node_ids
        if _semantic_node(base_nodes[item]) != _semantic_node(head_nodes[item])
    ]

    added_edge_ids = sorted(set(head_edges) - set(base_edges))
    removed_edge_ids = sorted(set(base_edges) - set(head_edges))
    all_nodes = {**base_nodes, **head_nodes}

    introduced_by_severity = Counter(item["severity"] for item in introduced)
    high_or_critical = sum(
        Severity.parse(item["severity"]) >= Severity.HIGH for item in introduced
    )

    return {
        "schema_version": 1,
        "base": {
            "ref": base_ref,
            "commit": base_commit,
            "coverage_incomplete": base_graph.coverage.incomplete,
            "adg_digest": base_graph.adg.canonical_digest() if base_graph.adg else None,
            "skipped_non_regular_git_entries": base_skipped_entries,
        },
        "head": {
            "ref": head_ref,
            "commit": head_commit,
            "coverage_incomplete": head_graph.coverage.incomplete,
            "adg_digest": head_graph.adg.canonical_digest() if head_graph.adg else None,
            "skipped_non_regular_git_entries": head_skipped_entries,
        },
        "summary": {
            "introduced_findings": len(introduced),
            "introduced_high_or_critical": high_or_critical,
            "introduced_findings_by_severity": dict(sorted(introduced_by_severity.items())),
            "resolved_findings": len(resolved),
            "changed_findings": len(changed_findings),
            "unchanged_findings": len(common_ids) - len(changed_findings),
            "added_authority_nodes": len(added_node_ids),
            "removed_authority_nodes": len(removed_node_ids),
            "changed_authority_nodes": len(changed_nodes),
            "added_authority_edges": len(added_edge_ids),
            "removed_authority_edges": len(removed_edge_ids),
        },
        "findings": {
            "introduced": introduced,
            "resolved": resolved,
            "changed": changed_findings,
        },
        "authority": {
            "added_nodes": [head_nodes[item] for item in added_node_ids],
            "removed_nodes": [base_nodes[item] for item in removed_node_ids],
            "changed_nodes": changed_nodes,
            "added_edges": [
                _edge_record(head_edges[item], all_nodes) for item in added_edge_ids
            ],
            "removed_edges": [
                _edge_record(base_edges[item], all_nodes) for item in removed_edge_ids
            ],
        },
    }


def build_git_diff(repo: Path, base_ref: str, head_ref: str) -> dict[str, Any]:
    """Materialize and scan two Git revisions, then compare their security models."""
    with ExitStack() as stack:
        base_snapshot: GitSnapshot = stack.enter_context(
            materialize_git_ref(repo, base_ref)
        )
        head_snapshot: GitSnapshot = stack.enter_context(
            materialize_git_ref(repo, head_ref)
        )

        base_config = load_config(base_snapshot.root, None)
        head_config = load_config(head_snapshot.root, None)
        base_graph, base_findings = scan(
            base_snapshot.root,
            use_default_suppressions=False,
            config=base_config,
        )
        head_graph, head_findings = scan(
            head_snapshot.root,
            use_default_suppressions=False,
            config=head_config,
        )
        return compare_scans(
            base_graph,
            base_findings,
            base_snapshot.root,
            head_graph,
            head_findings,
            head_snapshot.root,
            base_ref=base_ref,
            head_ref=head_ref,
            base_commit=base_snapshot.commit,
            head_commit=head_snapshot.commit,
            base_skipped_entries=base_snapshot.skipped_non_regular_entries,
            head_skipped_entries=head_snapshot.skipped_non_regular_entries,
        )


def _format_location(record: dict[str, Any]) -> str:
    location = record.get("location")
    if not location:
        return ""
    return f" {location['path']}:{location['line']}"


def render_console(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "HorusTrace Change Analysis",
        "=" * 32,
        f"Base: {report['base']['ref']} ({(report['base']['commit'] or 'unknown')[:12]})",
        f"Head: {report['head']['ref']} ({(report['head']['commit'] or 'unknown')[:12]})",
        "",
        "Summary",
        f"  Introduced findings: {summary['introduced_findings']} "
        f"({summary['introduced_high_or_critical']} high/critical)",
        f"  Resolved findings:   {summary['resolved_findings']}",
        f"  Changed findings:    {summary['changed_findings']}",
        f"  Authority nodes:     +{summary['added_authority_nodes']} "
        f"-{summary['removed_authority_nodes']} "
        f"~{summary['changed_authority_nodes']}",
        f"  Authority edges:     +{summary['added_authority_edges']} "
        f"-{summary['removed_authority_edges']}",
        f"  Coverage: base={'incomplete' if report['base']['coverage_incomplete'] else 'complete'}, "
        f"head={'incomplete' if report['head']['coverage_incomplete'] else 'complete'}",
    ]

    introduced = report["findings"]["introduced"]
    if introduced:
        lines.extend(["", "Introduced findings"])
        for item in introduced[:_MAX_CONSOLE_ITEMS]:
            agent = f" agent={item['agent']}" if item.get("agent") else ""
            lines.append(
                f"  + [{item['severity']}] {item['rule_id']}{agent}"
                f"{_format_location(item)} — {item['title']}"
            )
        if len(introduced) > _MAX_CONSOLE_ITEMS:
            lines.append(
                f"  ... {len(introduced) - _MAX_CONSOLE_ITEMS} more introduced findings"
            )

    added_nodes = report["authority"]["added_nodes"]
    changed_nodes = report["authority"]["changed_nodes"]
    if added_nodes or changed_nodes:
        lines.extend(["", "Authority changes"])
        for item in added_nodes[:_MAX_CONSOLE_ITEMS]:
            capabilities = item.get("attributes", {}).get("capabilities") or []
            suffix = f" capabilities={','.join(capabilities)}" if capabilities else ""
            lines.append(f"  + {item['kind']} {item['name']}{suffix}")
        remaining = max(0, _MAX_CONSOLE_ITEMS - min(len(added_nodes), _MAX_CONSOLE_ITEMS))
        for item in changed_nodes[:remaining]:
            detail = ""
            if item["added_capabilities"]:
                detail = f" +capabilities={','.join(item['added_capabilities'])}"
            lines.append(f"  ~ {item['kind']} {item['name']}{detail}")
        total = len(added_nodes) + len(changed_nodes)
        if total > _MAX_CONSOLE_ITEMS:
            lines.append(f"  ... {total - _MAX_CONSOLE_ITEMS} more authority changes")

    return "\n".join(lines)
