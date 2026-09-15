from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentreachguard import __version__
from agentreachguard.models import Severity
from agentreachguard.reporters.console import render as render_console
from agentreachguard.reporters.sarif import render as render_sarif
from agentreachguard.scanner import scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentreachguard", description="Security analysis for AI agents")
    parser.add_argument("--version", action="version", version=f"agentreachguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Scan an agent project")
    scan_parser.add_argument("path", nargs="?", default=".")
    scan_parser.add_argument("--format", choices=["console", "json", "sarif"], default="console")
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="high",
        help="Return exit code 2 when a finding at or above this severity is present.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "scan":
        return 0

    target = Path(args.path)
    if not target.exists():
        print(f"agentreachguard: target does not exist: {target}", file=sys.stderr)
        return 1

    graph, findings = scan(target)
    if args.format == "console":
        output = render_console(graph, findings, target)
    elif args.format == "json":
        output = json.dumps(
            {
                "version": __version__,
                "summary": {
                    "agents": len(graph.agents),
                    "tools": len(graph.all_tools()),
                    "mcp_servers": len(graph.all_mcp_servers()),
                    "identities": len(graph.all_identities()),
                    "attack_paths": len(graph.attack_paths),
                    "findings": len(findings),
                    "findings_by_layer": {
                        str(layer): sum(1 for finding in findings if finding.layer == layer)
                        for layer in range(1, 6)
                    },
                },
                "attack_paths": [
                    {
                        "path_id": path.path_id,
                        "title": path.title,
                        "agent": path.agent,
                        "severity": path.severity.label(),
                        "nodes": path.nodes,
                        "rationale": path.rationale,
                    }
                    for path in graph.attack_paths
                ],
                "findings": [f.as_dict() for f in findings],
            },
            indent=2,
        )
    else:
        output = json.dumps(render_sarif(findings), indent=2)

    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
