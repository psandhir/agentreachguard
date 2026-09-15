from __future__ import annotations

from collections import Counter
from pathlib import Path

from agentreachguard.models import Finding, Graph, Severity

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
        "AgentReachGuard Security Scan",
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
        "Coverage by analysis layer",
    ]
    for layer in range(1, 6):
        lines.append(f"  L{layer} {LAYER_NAMES[layer]}: {layer_counts[layer]} finding(s)")
    lines.append("")

    if not findings:
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
                finding.message,
            ]
        )
        if finding.evidence:
            lines.append("Evidence: " + " | ".join(finding.evidence))
        lines.append("Fix: " + finding.recommendation)
        lines.append("")
    return "\n".join(lines).rstrip()
