from __future__ import annotations

from collections import Counter
from pathlib import Path

from horustrace.models import Finding, Graph, Severity
from horustrace.provenance import control_observations

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
    lines = [
        "HorusTrace Security Scan",
        "=" * 23,
        f"Target:        {root}",
        f"Agents:        {len(graph.agents)}",
        f"Tools:         {len(graph.all_tools())}",
        f"MCP servers:   {len(graph.all_mcp_servers())}",
        f"Identities:    {len(graph.all_identities())}",
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
    lines.append("")

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
