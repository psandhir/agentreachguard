from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, date, datetime
from pathlib import Path

from agentreachguard import __version__
from agentreachguard.adapters.manifest import ManifestError
from agentreachguard.benchmark import BenchmarkError
from agentreachguard.benchmark import render_console as render_benchmark_console
from agentreachguard.benchmark import render_json as render_benchmark_json
from agentreachguard.benchmark import run as run_benchmark
from agentreachguard.models import Severity
from agentreachguard.provenance import control_observations
from agentreachguard.reporters.console import render as render_console
from agentreachguard.reporters.sarif import render as render_sarif
from agentreachguard.scanner import scan
from agentreachguard.suppressions import SuppressionError, write_baseline


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentreachguard", description="Security analysis for AI agents")
    parser.add_argument("--version", action="version", version=f"agentreachguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Scan an agent project")
    scan_parser.add_argument("path", nargs="?", default=".")
    scan_parser.add_argument("--format", choices=["console", "json", "sarif"], default="console")
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument("--suppressions", type=Path,
                             help="Explicit suppression YAML file.")
    scan_parser.add_argument("--strict", action="store_true",
                             help="Return exit code 1 when analysis is incomplete.")
    scan_parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="high",
        help="Return exit code 2 when a finding at or above this severity is present.",
    )
    baseline_parser = sub.add_parser("baseline", help="Create expiring suppressions for current findings")
    baseline_parser.add_argument("path", nargs="?", default=".")
    baseline_parser.add_argument("--output", type=Path,
                                 default=Path(".agentreachguard.suppressions.yaml"))
    baseline_parser.add_argument("--reason", required=True)
    baseline_parser.add_argument("--expires", required=True,
                                 help="Required expiry date in YYYY-MM-DD format.")
    baseline_parser.add_argument("--force", action="store_true",
                                 help="Replace an existing output file.")
    benchmark_parser = sub.add_parser("benchmark", help="Run a reviewed expectation corpus")
    benchmark_parser.add_argument("manifest", nargs="?", type=Path,
                                  default=Path("benchmarks/cases.yaml"))
    benchmark_parser.add_argument("--format", choices=["console", "json"], default="console")
    benchmark_parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "benchmark":
        try:
            report = run_benchmark(args.manifest)
        except BenchmarkError as exc:
            print(f"agentreachguard: {exc}", file=sys.stderr)
            return 1
        output = (render_benchmark_json(report) if args.format == "json"
                  else render_benchmark_console(report))
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        summary = report["summary"]
        return 0 if summary["passed"] == summary["cases"] else 1
    target = Path(args.path)
    if not target.exists():
        print(f"agentreachguard: target does not exist: {target}", file=sys.stderr)
        return 1

    try:
        if args.command == "baseline":
            if not args.reason.strip():
                print("agentreachguard: --reason must not be blank", file=sys.stderr)
                return 1
            try:
                expiry = date.fromisoformat(args.expires)
            except ValueError:
                print("agentreachguard: --expires must be YYYY-MM-DD", file=sys.stderr)
                return 1
            if expiry < datetime.now(tz=UTC).date():
                print("agentreachguard: --expires must not be in the past", file=sys.stderr)
                return 1
            if args.output.exists() and not args.force:
                print("agentreachguard: baseline output exists; use --force to replace it",
                      file=sys.stderr)
                return 1
            graph, findings = scan(target, use_default_suppressions=False)
            if graph.coverage.incomplete:
                print("agentreachguard: baseline refused because analysis is incomplete",
                      file=sys.stderr)
                return 1
            baseline_root = target.resolve() if target.is_dir() else target.resolve().parent
            write_baseline(findings, baseline_root, args.output, args.reason.strip(), expiry)
            print(f"Wrote {len(findings)} expiring suppressions to {args.output}")
            return 0
        graph, findings = scan(target, suppressions_path=args.suppressions)
    except (ManifestError, SuppressionError) as exc:
        print(f"agentreachguard: {exc}", file=sys.stderr)
        return 1
    if args.format == "console":
        output = render_console(graph, findings, target)
    elif args.format == "json":
        output = json.dumps(
            {
                "version": __version__,
                "coverage": graph.coverage.as_dict(),
                "control_observations": control_observations(graph),
                "suppressions": {
                    "suppressed_findings": [f.as_dict() for f in graph.suppressed_findings],
                    "diagnostics": graph.suppression_diagnostics,
                },
                "summary": {
                    "agents": len(graph.agents),
                    "tools": len(graph.all_tools()),
                    "mcp_servers": len(graph.all_mcp_servers()),
                    "identities": len(graph.all_identities()),
                    "attack_paths": len(graph.attack_paths),
                    "findings": len(findings),
                    "suppressed_findings": len(graph.suppressed_findings),
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
                        "assessment": path.metadata.get("assessment", "potential_risk"),
                        "basis": path.metadata.get("basis", "capability_cooccurrence"),
                        "exploitability": "not_verified",
                        "limitations": path.metadata.get("limitations", []),
                    }
                    for path in graph.attack_paths
                ],
                "findings": [f.as_dict() for f in findings],
            },
            indent=2,
        )
    else:
        output = json.dumps(render_sarif(
            findings, graph.coverage, control_observations(graph),
            graph.suppressed_findings, graph.suppression_diagnostics,
        ), indent=2)

    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    expired_suppression = any(d["status"] == "expired" for d in graph.suppression_diagnostics)
    if args.strict and (graph.coverage.incomplete or expired_suppression):
        return 1

    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
