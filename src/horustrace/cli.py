from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, date, datetime
from pathlib import Path

from horustrace import __version__
from horustrace.adapters.manifest import ManifestError
from horustrace.aibom import build_aibom
from horustrace.benchmark import BenchmarkError
from horustrace.benchmark import render_console as render_benchmark_console
from horustrace.benchmark import render_json as render_benchmark_json
from horustrace.benchmark import run as run_benchmark
from horustrace.change_analysis import build_git_diff
from horustrace.change_analysis import render_console as render_diff_console
from horustrace.change_analysis import render_markdown as render_diff_markdown
from horustrace.config import ConfigError, load_config
from horustrace.git_snapshot import GitSnapshotError
from horustrace.limits import ScanLimitError
from horustrace.mcp_effective import (
    effective_mcp_authority_report,
    render_effective_mcp_authority_console,
)
from horustrace.models import Severity
from horustrace.provenance import control_observations
from horustrace.reporters.console import render as render_console
from horustrace.reporters.sarif import render as render_sarif
from horustrace.rule_registry import iter_rule_metadata
from horustrace.scanner import ScannerError, scan
from horustrace.source_context import SOURCE_CONTEXTS
from horustrace.suppressions import SuppressionError, write_baseline


def _parse_excluded_source_contexts(values: list[str]) -> set[str]:
    contexts = {
        item.strip().lower().replace("_", "-")
        for value in values
        for item in value.split(",")
        if item.strip()
    }
    invalid = sorted(contexts - set(SOURCE_CONTEXTS))
    if invalid:
        raise ValueError(
            "unknown source context(s): "
            + ", ".join(invalid)
            + "; expected one of: "
            + ", ".join(SOURCE_CONTEXTS)
        )
    return contexts


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="horustrace", description="Security analysis for AI agents")
    parser.add_argument("--version", action="version", version=f"horustrace {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Scan an agent project")
    scan_parser.add_argument("path", nargs="?", default=".")
    scan_parser.add_argument("--format", choices=["console", "json", "sarif"], default="console")
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument("--config", type=Path, help="Repository scanner configuration YAML file.")
    scan_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Checked-out Terraform repository containing declared IAM bindings.",
    )
    scan_parser.add_argument("--suppressions", type=Path,
                             help="Explicit suppression YAML file.")
    scan_parser.add_argument(
        "--exclude-source-context",
        "--exclude-source-role",
        dest="exclude_source_context",
        action="append",
        default=[],
        metavar="CONTEXTS",
        help=(
            "Comma-separated finding source contexts to exclude from active reporting "
            "and fail-on evaluation. Coverage is not suppressed."
        ),
    )
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
                                 default=Path(".horustrace.suppressions.yaml"))
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
    rules_parser = sub.add_parser("rules", help="List the built-in security rule catalogue")
    rules_parser.add_argument("--format", default="console", metavar="FORMAT")
    rules_parser.add_argument("--output", type=Path)
    graph_parser = sub.add_parser("graph", help="Export the Agent Dependency Graph")
    graph_parser.add_argument("path", nargs="?", default=".")
    graph_parser.add_argument("--output", type=Path)
    graph_parser.add_argument("--config", type=Path)
    graph_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Checked-out Terraform repository containing declared IAM bindings.",
    )
    authority_parser = sub.add_parser(
        "authority",
        help="Show effective agent-to-MCP authority relationships",
    )
    authority_parser.add_argument("path", nargs="?", default=".")
    authority_parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
    )
    authority_parser.add_argument("--output", type=Path)
    authority_parser.add_argument("--config", type=Path)
    aibom_parser = sub.add_parser("aibom", help="Generate an Agent Bill of Materials")
    aibom_parser.add_argument("path", nargs="?", default=".")
    aibom_parser.add_argument("--output", type=Path)
    aibom_parser.add_argument("--config", type=Path)
    aibom_parser.add_argument(
        "--authority-source",
        type=Path,
        help="Checked-out Terraform repository containing declared IAM bindings.",
    )
    diff_parser = sub.add_parser(
        "diff",
        help="Compare findings and effective authority across two Git revisions",
    )
    diff_parser.add_argument(
        "revision_range",
        metavar="BASE..HEAD",
        help="Two Git revisions separated by '..', for example origin/main..HEAD.",
    )
    diff_parser.add_argument(
        "--repo",
        type=Path,
        default=Path("."),
        help="Path inside the Git repository to compare (default: current directory).",
    )
    diff_parser.add_argument(
        "--format",
        choices=["console", "json", "markdown"],
        default="console",
    )
    diff_parser.add_argument("--output", type=Path)
    diff_parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 1 when either revision has incomplete analysis.",
    )
    diff_parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="high",
        help=(
            "Return exit code 2 when an introduced finding meets the severity threshold."
        ),
    )
    return parser


def _rule_catalogue_json() -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "layer": rule.layer,
                    "title": rule.title,
                    "default_severity": rule.default_severity.label(),
                    "category": rule.category,
                    "assessment": rule.assessment,
                    "rationale": rule.rationale,
                    "remediation": rule.remediation,
                    "references": list(rule.references),
                    "owasp_agentic": list(rule.owasp_agentic),
                }
                for rule in iter_rule_metadata()
            ],
        },
        indent=2,
    )


def _rule_catalogue_console() -> str:
    lines = ["HorusTrace Rule Catalogue", "=" * 30, ""]
    for rule in iter_rule_metadata():
        lines.extend(
            [
                f"{rule.rule_id}  L{rule.layer}  {rule.default_severity.label()}  {rule.title}",
                f"  Category: {rule.category}; assessment: {rule.assessment}",
                f"  Rationale: {rule.rationale}",
                f"  Remediation: {rule.remediation}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def _parse_revision_range(value: str) -> tuple[str, str]:
    if "..." in value or value.count("..") != 1:
        raise ValueError("revision range must use BASE..HEAD")
    base_ref, head_ref = (item.strip() for item in value.split("..", 1))
    if not base_ref or not head_ref:
        raise ValueError("revision range must include both BASE and HEAD")
    return base_ref, head_ref


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "rules":
        if args.format not in {"console", "json"}:
            print(
                "horustrace: rules --format must be one of: console, json",
                file=sys.stderr,
            )
            return 1
        output = _rule_catalogue_json() if args.format == "json" else _rule_catalogue_console()
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return 0
    if args.command == "benchmark":
        try:
            report = run_benchmark(args.manifest)
        except BenchmarkError as exc:
            print(f"horustrace: {exc}", file=sys.stderr)
            return 1
        output = (render_benchmark_json(report) if args.format == "json"
                  else render_benchmark_console(report))
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        summary = report["summary"]
        return 0 if summary["passed"] == summary["cases"] else 1
    if args.command == "diff":
        try:
            base_ref, head_ref = _parse_revision_range(args.revision_range)
            report = build_git_diff(args.repo, base_ref, head_ref)
        except (
            ValueError,
            GitSnapshotError,
            ConfigError,
            ManifestError,
            ScannerError,
            SuppressionError,
            ScanLimitError,
        ) as exc:
            print(f"horustrace: {exc}", file=sys.stderr)
            return 1

        if args.format == "json":
            output = json.dumps(report, indent=2)
        elif args.format == "markdown":
            output = render_diff_markdown(report)
        else:
            output = render_diff_console(report)
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)

        if args.strict and (
            report["base"]["analysis_incomplete"]
            or report["head"]["analysis_incomplete"]
        ):
            return 1
        if args.fail_on != "none":
            threshold = Severity.parse(args.fail_on)
            introduced_at_threshold = any(
                Severity.parse(item["severity"]) >= threshold
                for item in report["findings"]["introduced"]
            )
            worsened_at_threshold = any(
                Severity.parse(item["after"]["severity"]) >= threshold
                for item in report["findings"]["worsened"]
            )
            if introduced_at_threshold or worsened_at_threshold:
                return 2
        return 0
    excluded_source_contexts: set[str] = set()
    if args.command == "scan":
        try:
            excluded_source_contexts = _parse_excluded_source_contexts(
                args.exclude_source_context
            )
        except ValueError as exc:
            print(f"horustrace: {exc}", file=sys.stderr)
            return 1

    target = Path(args.path)
    if not target.exists():
        print(f"horustrace: target does not exist: {target}", file=sys.stderr)
        return 1

    if args.command in {"graph", "aibom", "authority"}:
        try:
            root = target if target.is_dir() else target.parent
            config = load_config(root, args.config)
            graph, _ = scan(
                target,
                config=config,
                authority_source=getattr(args, "authority_source", None),
            )
        except (ConfigError, ManifestError, ScannerError, SuppressionError, ScanLimitError) as exc:
            print(f"horustrace: {exc}", file=sys.stderr)
            return 1

        if args.command == "authority":
            report = effective_mcp_authority_report(graph)
            output = (
                json.dumps(report, indent=2)
                if args.format == "json"
                else render_effective_mcp_authority_console(graph, target)
            )
        else:
            if graph.adg is None:
                print("horustrace: Agent Dependency Graph was not generated", file=sys.stderr)
                return 1
            document = (
                graph.adg.as_dict()
                if args.command == "graph"
                else build_aibom(graph.adg)
            )
            output = json.dumps(document, indent=2)

        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return 0

    try:
        if args.command == "baseline":
            if not args.reason.strip():
                print("horustrace: --reason must not be blank", file=sys.stderr)
                return 1
            try:
                expiry = date.fromisoformat(args.expires)
            except ValueError:
                print("horustrace: --expires must be YYYY-MM-DD", file=sys.stderr)
                return 1
            if expiry < datetime.now(tz=UTC).date():
                print("horustrace: --expires must not be in the past", file=sys.stderr)
                return 1
            if args.output.exists() and not args.force:
                print("horustrace: baseline output exists; use --force to replace it",
                      file=sys.stderr)
                return 1
            graph, findings = scan(target, use_default_suppressions=False)
            if graph.coverage.incomplete:
                print("horustrace: baseline refused because analysis is incomplete",
                      file=sys.stderr)
                return 1
            baseline_root = target.resolve() if target.is_dir() else target.resolve().parent
            write_baseline(findings, baseline_root, args.output, args.reason.strip(), expiry)
            print(f"Wrote {len(findings)} expiring suppressions to {args.output}")
            return 0
        config = load_config(target if target.is_dir() else target.parent, args.config)
        graph, findings = scan(
            target,
            suppressions_path=args.suppressions,
            config=config,
            authority_source=args.authority_source,
        )
        disabled_rules = graph.configuration_audit.get("disabled_rules", [])
        source_context_counts_before = {
            context: sum(
                finding.source_context == context for finding in findings
            )
            for context in SOURCE_CONTEXTS
            if any(finding.source_context == context for finding in findings)
        }
        excluded_source_context_counts = {
            context: sum(
                finding.source_context == context for finding in findings
            )
            for context in sorted(excluded_source_contexts)
            if any(finding.source_context == context for finding in findings)
        }
        if excluded_source_contexts:
            findings = [
                finding
                for finding in findings
                if finding.source_context not in excluded_source_contexts
            ]
        source_context_counts_after = {
            context: sum(
                finding.source_context == context for finding in findings
            )
            for context in SOURCE_CONTEXTS
            if any(finding.source_context == context for finding in findings)
        }
        graph.configuration_audit.update(
            {
                "excluded_source_contexts": sorted(excluded_source_contexts),
                "excluded_findings_by_source_context": dict(
                    sorted(excluded_source_context_counts.items())
                ),
                "source_context_counts_before_filter": dict(
                    sorted(source_context_counts_before.items())
                ),
                "source_context_counts_after_filter": dict(
                    sorted(source_context_counts_after.items())
                ),
            }
        )
    except (ConfigError, ManifestError, ScannerError, SuppressionError, ScanLimitError) as exc:
        print(f"horustrace: {exc}", file=sys.stderr)
        return 1
    if args.format == "console":
        output = render_console(graph, findings, target)
    elif args.format == "json":
        output = json.dumps(
            {
                "version": __version__,
                "coverage": graph.coverage.as_dict(),
                "control_observations": control_observations(graph),
                "mcp_authority": effective_mcp_authority_report(graph),
                "configuration": {
                    "path": str(config.source_path) if config.source_path else None,
                    "repository": {"strict": config.strict},
                    "cli_overrides": {
                        "strict": bool(args.strict),
                        "exclude_source_contexts": sorted(excluded_source_contexts),
                    },
                    "effective": {
                        "strict": bool(args.strict or config.strict),
                        "exclude_source_contexts": sorted(excluded_source_contexts),
                    },
                    "disabled_rules": disabled_rules,
                    "rule_overrides": {
                        rule_id: {
                            "enabled": override.enabled,
                            "severity": (
                                override.severity.label()
                                if override.severity
                                else None
                            ),
                        }
                        for rule_id, override in config.rules.items()
                    },
                },
                "suppressions": {
                    "suppressed_findings": [f.as_dict() for f in graph.suppressed_findings],
                    "diagnostics": graph.suppression_diagnostics,
                },
                "summary": {
                    "agents": len(graph.agents),
                    "tools": len(graph.all_tools()),
                    "mcp_servers": len(graph.all_mcp_servers()),
                    "identities": len(graph.all_identities()),
                    "flow_paths": len(graph.flow_paths),
                    "flow_execution_contexts": (
                        graph.coverage.resolution.get("flows", {}).get(
                            "execution_contexts",
                            {},
                        )
                    ),
                    "flow_agent_reachability": (
                        graph.coverage.resolution.get("flows", {}).get(
                            "agent_reachability",
                            {},
                        )
                    ),
                    "flow_agent_attribution_gaps": (
                        graph.coverage.resolution.get("flows", {}).get(
                            "agent_attribution_gaps",
                            0,
                        )
                    ),
                    "attack_paths": len(graph.attack_paths),
                    "adg_nodes": len(graph.adg.nodes) if graph.adg else 0,
                    "adg_edges": len(graph.adg.edges) if graph.adg else 0,
                    "findings": len(findings),
                    "suppressed_findings": len(graph.suppressed_findings),
                    "findings_by_source_context": dict(
                        sorted(source_context_counts_after.items())
                    ),
                    "findings_by_source_context_before_filter": dict(
                        sorted(source_context_counts_before.items())
                    ),
                    "excluded_findings": sum(
                        excluded_source_context_counts.values()
                    ),
                    "excluded_findings_by_source_context": dict(
                        sorted(excluded_source_context_counts.items())
                    ),
                    "findings_by_layer": {
                        str(layer): sum(1 for finding in findings if finding.layer == layer)
                        for layer in range(1, 6)
                    },
                },
                "flow_paths": [flow.as_dict() for flow in graph.flow_paths],
                "adg": {
                    "schema_version": 1,
                    "digest": graph.adg.canonical_digest() if graph.adg else None,
                    "summary": graph.adg.as_dict()["summary"] if graph.adg else None,
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
                        "flow_id": path.metadata.get("flow_id"),
                        "exploitability": "not_verified",
                        "confidence": next(
                            (
                                finding.confidence.value
                                for finding in findings
                                if finding.rule_id == path.path_id
                                and finding.agent == path.agent
                                and finding.confidence is not None
                            ),
                            None,
                        ),
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
            graph.flow_paths,
        ), indent=2)

    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    expired_suppression = any(d["status"] == "expired" for d in graph.suppression_diagnostics)
    if (args.strict or config.strict) and (graph.coverage.incomplete or expired_suppression):
        return 1

    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
