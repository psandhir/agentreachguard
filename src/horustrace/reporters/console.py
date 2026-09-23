from __future__ import annotations

from collections import Counter
from pathlib import Path

from horustrace.models import Finding, Graph, Severity
from horustrace.provenance import control_observations
from horustrace.source_context import SOURCE_CONTEXTS

LAYER_NAMES = {
    1: "Agent configuration",
    2: "Capability analysis",
    3: "Identity & permissions",
    4: "Data & network reachability",
    5: "Attack-path analysis",
}


def render(graph: Graph, findings: list[Finding], root: Path) -> str:
    counts = Counter(f.severity for f in findings)
    layer_counts = Counter(f.layer for f in findings)
    source_context_counts = Counter(f.source_context for f in findings)
    excluded_source_context_counts = graph.configuration_audit.get(
        "excluded_findings_by_source_context",
        {},
    )
    flow_resolution = graph.coverage.resolution.get("flows", {})
    flow_reachability = flow_resolution.get("agent_reachability", {})
    lines = [
        "HorusTrace Security Scan",
        "=" * 23,
        f"Target:        {root}",
        f"Agents:        {len(graph.agents)}",
        f"Tools:         {len(graph.all_tools())}",
        f"MCP servers:   {len(graph.all_mcp_servers())}",
        f"Identities:    {len(graph.all_identities())}",
        f"Flows:         {len(graph.flow_paths)}",
        (
            "  Reachability: "
            f"agent={flow_reachability.get('proven_agent_reachable', 0)}, "
            f"non-agent={flow_reachability.get('proven_non_agent', 0)}, "
            f"unknown={flow_reachability.get('unknown', 0)}"
        ),
        (
            "  Attribution gaps: "
            f"{flow_resolution.get('agent_attribution_gaps', 0)}"
        ),
        f"Attack paths:  {len(graph.attack_paths)}",
        "",
        "Findings",
        f"  Critical: {counts[Severity.CRITICAL]}",
        f"  High:     {counts[Severity.HIGH]}",
        f"  Medium:   {counts[Severity.MEDIUM]}",
        f"  Low:      {counts[Severity.LOW]}",
        "",
        "Findings by analysis layer",
    ]
    for layer in range(1, 6):
        lines.append(f"  L{layer} {LAYER_NAMES[layer]}: {layer_counts[layer]} finding(s)")
    lines.extend(["", "Findings by source context"])
    for source_context in SOURCE_CONTEXTS:
        lines.append(
            f"  {source_context}: {source_context_counts[source_context]} finding(s)"
        )
    if excluded_source_context_counts:
        lines.append(
            "  Excluded by source-context filter: "
            + ", ".join(
                f"{context}={count}"
                for context, count in sorted(excluded_source_context_counts.items())
            )
        )
    lines.append("")

    gcp_iam = graph.configuration_audit.get("gcp_iam_export")
    if gcp_iam:
        lines.extend(
            [
                "GCP IAM enrichment",
                f"  Export: {gcp_iam.get('path')}",
                f"  Records: {gcp_iam.get('records', 0)}",
                (
                    "  Service-account bindings: "
                    f"{gcp_iam.get('service_account_bindings', 0)}"
                ),
                f"  Matched identities: {gcp_iam.get('matched_identities', 0)}",
                f"  Matched bindings: {gcp_iam.get('matched_bindings', 0)}",
                (
                    "  Conditional matched bindings: "
                    f"{gcp_iam.get('conditional_matched_bindings', 0)}"
                ),
                "",
            ]
        )

    if graph.suppressed_findings or graph.suppression_diagnostics:
        lines.append("Suppressions")
        lines.append(f"  Findings suppressed: {len(graph.suppressed_findings)}")
        for diagnostic in graph.suppression_diagnostics:
            suffix = f" ({diagnostic.get('matches', 0)} match(es))" if "matches" in diagnostic else ""
            lines.append(f"  {diagnostic['id']}: {diagnostic['status']}{suffix}; "
                         f"expires {diagnostic['expires']}; reason: {diagnostic['reason']}")
        lines.append("")

    coverage = graph.coverage
    lines.extend([
        "Scan coverage",
        f"  Files considered: {coverage.files_considered}",
        (f"  Files scanned: {coverage.files_scanned}; skipped: {coverage.files_skipped}; "
         f"failed: {coverage.files_failed}"),
        "  Analysis status: " + ("incomplete" if coverage.incomplete else "no detected gaps"),
    ])
    for diagnostic in coverage.diagnostics:
        location = diagnostic.location
        prefix = f"{location.path}:{location.line}: " if location else ""
        lines.append(f"  {diagnostic.code}: {prefix}{diagnostic.message}")
    lines.append("")

    controls = control_observations(graph)
    if controls:
        lines.append("Control observations (runtime effectiveness not verified)")
        for control in controls:
            lines.append(f"  {control['subject']}: {control['control']} "
                         f"{control['configuration']}")
        lines.append("")

    if not findings:
        if graph.suppressed_findings:
            lines.append(
                f"No active findings; {len(graph.suppressed_findings)} finding(s) suppressed."
            )
        else:
            lines.append("No findings detected by the current rule set.")
        return "\n".join(lines)

    for finding in findings:
        location = ""
        if finding.location:
            location = f"{finding.location.path}:{finding.location.line}"
        lines.extend(
            [
                f"[{finding.severity.name}] L{finding.layer} {finding.rule_id} — {finding.title}",
                f"Location: {location or 'n/a'}",
                f"Agent:    {finding.agent or 'n/a'}",
                f"Assessment: {finding.assessment}",
                f"Fingerprint: {finding.fingerprint or 'n/a'}",
                finding.message,
            ]
        )
        if finding.confidence is not None:
            lines.append(f"Confidence: {finding.confidence.value}")
        if finding.evidence:
            lines.append("Evidence: " + " | ".join(finding.evidence))
        if finding.provenance:
            counts = Counter(fact.origin for fact in finding.provenance)
            lines.append("Evidence origins: " + ", ".join(
                f"{origin} ({count})" for origin, count in sorted(counts.items())
            ))
        for limitation in finding.limitations:
            lines.append("Limit: " + limitation)
        lines.append("Fix: " + finding.recommendation)
        lines.append("")
    return "\n".join(lines).rstrip()
