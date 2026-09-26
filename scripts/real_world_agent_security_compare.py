"""Compare a candidate HorusTrace frozen-cohort run with the immutable baseline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

STUDY = "real-world-agent-security-2026"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def metric(report: dict[str, Any], *path: str) -> float | None:
    current: Any = report
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return number(current)


def delta(candidate: float | None, baseline: float | None) -> float | None:
    if candidate is None or baseline is None:
        return None
    return round(candidate - baseline, 4)


def gate(name: str, value: float | None, threshold: float, operator: str = ">=") -> dict[str, Any]:
    if operator != ">=":
        raise ValueError(f"unsupported gate operator: {operator}")
    return {
        "name": name,
        "value": value,
        "operator": operator,
        "threshold": threshold,
        "meets": bool(value is not None and value >= threshold),
    }


def compare(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    if baseline.get("study") != STUDY or candidate.get("study") != STUDY:
        raise ValueError("both reports must belong to the real-world-agent-security-2026 study")
    if baseline.get("cohort_cases") != candidate.get("cohort_cases"):
        raise ValueError("candidate cohort size differs from frozen baseline")
    if candidate.get("execution_mode") not in {None, "postfix"}:
        raise ValueError("candidate report must be a post-fix frozen-cohort execution")

    dimensions = [
        "agent_entities",
        "tools",
        "mcp_servers",
        "delegation_edges",
        "effective_authority",
    ]
    metric_deltas: dict[str, Any] = {}
    regressions: list[dict[str, Any]] = []
    for dimension in dimensions:
        metric_deltas[dimension] = {}
        for measure in ("precision", "recall"):
            before = metric(baseline, "metrics", dimension, measure)
            after = metric(candidate, "metrics", dimension, measure)
            change = delta(after, before)
            metric_deltas[dimension][measure] = {
                "baseline": before,
                "candidate": after,
                "delta": change,
            }
            if change is not None and change < 0:
                regressions.append(
                    {
                        "scope": "overall",
                        "dimension": dimension,
                        "measure": measure,
                        "baseline": before,
                        "candidate": after,
                        "delta": change,
                    }
                )

    framework_deltas: dict[str, Any] = {}
    frameworks = sorted(
        set((baseline.get("per_framework") or {}))
        | set((candidate.get("per_framework") or {}))
    )
    for framework in frameworks:
        framework_deltas[framework] = {}
        for dimension in ("agent_entities", "tools", "mcp_servers", "effective_authority"):
            framework_deltas[framework][dimension] = {}
            for measure in ("precision", "recall"):
                before = metric(
                    baseline,
                    "per_framework",
                    framework,
                    dimension,
                    measure,
                )
                after = metric(
                    candidate,
                    "per_framework",
                    framework,
                    dimension,
                    measure,
                )
                change = delta(after, before)
                framework_deltas[framework][dimension][measure] = {
                    "baseline": before,
                    "candidate": after,
                    "delta": change,
                }
                if change is not None and change < 0:
                    regressions.append(
                        {
                            "scope": framework,
                            "dimension": dimension,
                            "measure": measure,
                            "baseline": before,
                            "candidate": after,
                            "delta": change,
                        }
                    )

    successful = int((candidate.get("summary") or {}).get("successful_cases", 0))
    cohort_cases = int(candidate.get("cohort_cases", 0))
    execution_success = successful / cohort_cases if cohort_cases else None

    gates = [
        gate(
            "overall_agent_precision",
            metric(candidate, "metrics", "agent_entities", "precision"),
            0.95,
        ),
        gate(
            "langgraph_agent_recall",
            metric(candidate, "per_framework", "langgraph", "agent_entities", "recall"),
            0.80,
        ),
        gate(
            "langgraph_tool_recall",
            metric(candidate, "per_framework", "langgraph", "tools", "recall"),
            0.70,
        ),
        gate(
            "mcp_custom_agent_recall",
            metric(candidate, "per_framework", "mcp-custom", "agent_entities", "recall"),
            0.60,
        ),
        gate(
            "mcp_custom_tool_recall",
            metric(candidate, "per_framework", "mcp-custom", "tools", "recall"),
            0.60,
        ),
        gate(
            "explicit_mcp_server_recall",
            metric(candidate, "metrics", "mcp_servers", "recall"),
            0.85,
        ),
        gate(
            "delegation_precision",
            metric(candidate, "metrics", "delegation_edges", "precision"),
            0.90,
        ),
        gate("scanner_execution_success", execution_success, 1.0),
    ]

    baseline_failures = {
        str(item.get("case_id"))
        for item in baseline.get("execution_failures") or []
        if isinstance(item, dict)
    }
    candidate_failures = {
        str(item.get("case_id"))
        for item in candidate.get("execution_failures") or []
        if isinstance(item, dict)
    }

    baseline_incomplete = int((baseline.get("summary") or {}).get("analysis_incomplete_cases", 0))
    candidate_incomplete = int((candidate.get("summary") or {}).get("analysis_incomplete_cases", 0))

    return {
        "schema_version": 1,
        "study": STUDY,
        "baseline_scanner_sha": baseline.get("scanner_sha"),
        "candidate_scanner_sha": candidate.get("scanner_sha"),
        "cohort_cases": cohort_cases,
        "metric_deltas": metric_deltas,
        "per_framework_deltas": framework_deltas,
        "v09_gates": gates,
        "v09_gates_met": all(item["meets"] for item in gates),
        "regressions": regressions,
        "execution": {
            "baseline_successful": (baseline.get("summary") or {}).get("successful_cases"),
            "candidate_successful": successful,
            "new_failures": sorted(candidate_failures - baseline_failures),
            "fixed_failures": sorted(baseline_failures - candidate_failures),
        },
        "analysis_incomplete": {
            "baseline": baseline_incomplete,
            "candidate": candidate_incomplete,
            "delta": candidate_incomplete - baseline_incomplete,
        },
    }


def fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# HorusTrace v0.9 Frozen-Cohort Delta",
        "",
        f"- Baseline scanner: `{report['baseline_scanner_sha']}`",
        f"- Candidate scanner: `{report['candidate_scanner_sha']}`",
        f"- Frozen cohort: {report['cohort_cases']} repositories",
        "",
        "## Overall metric deltas",
        "",
        "| Dimension | Measure | Baseline | Candidate | Delta |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for dimension, values in report["metric_deltas"].items():
        for measure, item in values.items():
            lines.append(
                f"| {dimension} | {measure} | {fmt(item['baseline'])} | "
                f"{fmt(item['candidate'])} | {fmt(item['delta'])} |"
            )

    lines.extend(
        [
            "",
            "## v0.9 release gates",
            "",
            "| Gate | Candidate | Required | Meets |",
            "| --- | ---: | ---: | --- |",
        ]
    )
    for item in report["v09_gates"]:
        lines.append(
            f"| {item['name']} | {fmt(item['value'])} | "
            f"{item['operator']} {fmt(item['threshold'])} | "
            f"{'yes' if item['meets'] else 'no'} |"
        )

    execution = report["execution"]
    lines.extend(
        [
            "",
            "## Execution",
            "",
            f"- Baseline successful: {execution['baseline_successful']}",
            f"- Candidate successful: {execution['candidate_successful']}",
            f"- Fixed failures: {', '.join(execution['fixed_failures']) or 'none'}",
            f"- New failures: {', '.join(execution['new_failures']) or 'none'}",
            f"- Analysis-incomplete delta: {report['analysis_incomplete']['delta']:+d}",
            "",
            "## Regressions",
            "",
        ]
    )
    if report["regressions"]:
        lines.extend(
            [
                "| Scope | Dimension | Measure | Baseline | Candidate | Delta |",
                "| --- | --- | --- | ---: | ---: | ---: |",
            ]
        )
        for item in report["regressions"]:
            lines.append(
                f"| {item['scope']} | {item['dimension']} | {item['measure']} | "
                f"{fmt(item['baseline'])} | {fmt(item['candidate'])} | "
                f"{fmt(item['delta'])} |"
            )
    else:
        lines.append("No measured precision/recall regression against the frozen baseline.")

    lines.extend(
        [
            "",
            "The immutable baseline and locked source reference are not modified by this report.",
            "",
        ]
    )
    return "\n".join(lines)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--output-json", type=Path, required=True)
    p.add_argument("--output-markdown", type=Path, required=True)
    p.add_argument(
        "--enforce-v09-gates",
        action="store_true",
        help="Exit non-zero unless every v0.9 release gate is met.",
    )
    return p


def main() -> int:
    args = parser().parse_args()
    report = compare(load_json(args.baseline), load_json(args.candidate))
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.output_markdown.write_text(render_markdown(report) + "\n", encoding="utf-8")
    print(render_markdown(report))
    if args.enforce_v09_gates and not report["v09_gates_met"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
