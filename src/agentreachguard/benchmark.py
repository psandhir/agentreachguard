"""Manually reviewed benchmark runner for scanner precision and recall."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from agentreachguard.scanner import scan


class BenchmarkError(ValueError):
    """The benchmark manifest is invalid."""


class _UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in keys
                keys.add(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    None, None, "invalid mapping key", key_node.start_mark,
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None, None, "duplicate mapping key", key_node.start_mark,
                )
        return super().construct_mapping(node, deep=deep)


def _key(rule_id: str, agent: str | None) -> str:
    return f"{rule_id}@{agent or '-'}"


def run(manifest: Path) -> dict[str, Any]:
    try:
        raw = yaml.load(manifest.read_text(encoding="utf-8"), Loader=_UniqueLoader)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise BenchmarkError(f"{manifest}: cannot read benchmark manifest") from exc
    if (not isinstance(raw, dict) or type(raw.get("version")) is not int
            or raw.get("version") != 1 or not isinstance(raw.get("cases"), list)):
        raise BenchmarkError(f"{manifest}: expected version 1 with a cases list")
    if set(raw) - {"version", "cases"}:
        raise BenchmarkError(f"{manifest}: unknown benchmark field")
    results = []
    total_tp = total_fp = total_fn = 0
    names = set()
    for index, case in enumerate(raw["cases"]):
        if not isinstance(case, dict) or set(case) != {"name", "path", "expected"}:
            raise BenchmarkError(f"{manifest}: cases[{index}] has invalid fields")
        if not all(isinstance(case.get(key), str) and case[key] for key in ("name", "path")):
            raise BenchmarkError(f"{manifest}: cases[{index}] needs name and path")
        if case["name"] in names:
            raise BenchmarkError(f"{manifest}: duplicate benchmark case name")
        names.add(case["name"])
        expected_list = case["expected"]
        if not isinstance(expected_list, list) or not all(
            isinstance(value, str) and "@" in value for value in expected_list
        ):
            raise BenchmarkError(f"{manifest}: cases[{index}].expected must contain RULE@agent keys")
        expected = Counter(expected_list)
        target = (manifest.parent / case["path"]).resolve()
        if not target.exists():
            raise BenchmarkError(f"{manifest}: benchmark path does not exist: {case['path']}")
        graph, findings = scan(target, use_default_suppressions=False)
        actual = Counter(_key(f.rule_id, f.agent) for f in findings)
        true_positive = sorted((actual & expected).elements())
        false_positive = sorted((actual - expected).elements())
        false_negative = sorted((expected - actual).elements())
        total_tp += len(true_positive)
        total_fp += len(false_positive)
        total_fn += len(false_negative)
        results.append({
            "name": case["name"], "path": case["path"],
            "passed": not false_positive and not false_negative and not graph.coverage.incomplete,
            "true_positive": true_positive, "false_positive": false_positive,
            "false_negative": false_negative, "coverage": graph.coverage.as_dict(),
        })
    precision = total_tp / (total_tp + total_fp) if total_tp + total_fp else 1.0
    recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 1.0
    return {
        "version": 1, "manifest": str(manifest),
        "summary": {
            "cases": len(results), "passed": sum(case["passed"] for case in results),
            "true_positive": total_tp, "false_positive": total_fp,
            "false_negative": total_fn, "precision": precision, "recall": recall,
        },
        "cases": results,
    }


def render_console(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "AgentReachGuard Reviewed Benchmark",
        "====================================",
        f"Cases: {summary['passed']}/{summary['cases']} passed",
        f"Precision: {summary['precision']:.3f}",
        f"Recall:    {summary['recall']:.3f}",
        f"False positives: {summary['false_positive']}",
        f"False negatives: {summary['false_negative']}",
        "",
    ]
    for case in report["cases"]:
        lines.append(f"[{'PASS' if case['passed'] else 'FAIL'}] {case['name']}")
        if case["false_positive"]:
            lines.append("  Unexpected: " + ", ".join(case["false_positive"]))
        if case["false_negative"]:
            lines.append("  Missing: " + ", ".join(case["false_negative"]))
        if case["coverage"]["incomplete"]:
            lines.append("  Coverage incomplete")
    return "\n".join(lines).rstrip()


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2)
