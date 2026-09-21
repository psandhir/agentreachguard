"""Manually reviewed benchmark runner for scanner precision and recall."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from horustrace.scanner import scan


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


def _validate_path_expectations(manifest: Path, case: dict[str, Any], index: int) -> list[dict[str, str]]:
    expectations = case.get("expected_paths", [])
    if not isinstance(expectations, list):
        raise BenchmarkError(f"{manifest}: cases[{index}].expected_paths must be a list")
    allowed = {"rule_id", "agent", "source_kind", "sink_kind", "basis", "confidence"}
    required = {"rule_id", "source_kind", "sink_kind", "basis"}
    result: list[dict[str, str]] = []
    for path_index, item in enumerate(expectations):
        field = f"cases[{index}].expected_paths[{path_index}]"
        if not isinstance(item, dict) or set(item) - allowed or not required <= set(item):
            raise BenchmarkError(f"{manifest}: {field} has invalid fields")
        if not all(isinstance(value, str) and value for value in item.values()):
            raise BenchmarkError(f"{manifest}: {field} values must be nonempty strings")
        result.append(dict(item))
    return result


def _path_expectation_label(expectation: dict[str, str]) -> str:
    agent = expectation.get("agent", "-")
    confidence = expectation.get("confidence", "*")
    return (
        f"{expectation['rule_id']}@{agent}:"
        f"{expectation['source_kind']}->{expectation['sink_kind']}:"
        f"{expectation['basis']}:{confidence}"
    )


def _path_expectation_matches(expectation: dict[str, str], graph, findings) -> bool:
    flow_by_id = {flow.flow_id: flow for flow in graph.flow_paths}
    for path in graph.attack_paths:
        if path.path_id != expectation["rule_id"]:
            continue
        if expectation.get("agent") and path.agent != expectation["agent"]:
            continue
        if path.metadata.get("basis", "capability_cooccurrence") != expectation["basis"]:
            continue
        flow_id = path.metadata.get("flow_id")
        flow = flow_by_id.get(flow_id)
        if flow is None:
            continue
        if flow.source_kind != expectation["source_kind"] or flow.sink_kind != expectation["sink_kind"]:
            continue
        expected_confidence = expectation.get("confidence")
        if expected_confidence:
            finding = next(
                (
                    item for item in findings
                    if item.rule_id == path.path_id
                    and item.agent == path.agent
                    and " -> ".join(path.nodes) in item.evidence
                ),
                None,
            )
            actual_confidence = finding.confidence.value if finding and finding.confidence else None
            if actual_confidence != expected_confidence:
                continue
        return True
    return False


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
        allowed_fields = {
            "name", "path", "expected", "expected_diagnostics", "expect_incomplete",
            "expected_paths",
        }
        if not isinstance(case, dict) or set(case) - allowed_fields or not {"name", "path", "expected"} <= set(case):
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
        expected_paths = _validate_path_expectations(manifest, case, index)
        expected_diagnostics = case.get("expected_diagnostics", [])
        if not isinstance(expected_diagnostics, list) or not all(
            isinstance(value, str) and value.startswith("ARG-COV-") for value in expected_diagnostics
        ):
            raise BenchmarkError(f"{manifest}: cases[{index}].expected_diagnostics must contain diagnostic IDs")
        expect_incomplete = case.get("expect_incomplete", False)
        if type(expect_incomplete) is not bool:
            raise BenchmarkError(f"{manifest}: cases[{index}].expect_incomplete must be boolean")
        target = (manifest.parent / case["path"]).resolve()
        if not target.exists():
            raise BenchmarkError(f"{manifest}: benchmark path does not exist: {case['path']}")
        graph, findings = scan(target, use_default_suppressions=False)
        actual = Counter(_key(f.rule_id, f.agent) for f in findings)
        true_positive = sorted((actual & expected).elements())
        false_positive = sorted((actual - expected).elements())
        false_negative = sorted((expected - actual).elements())
        actual_diagnostics = {d.diagnostic_id for d in graph.coverage.diagnostics}
        missing_diagnostics = sorted(set(expected_diagnostics) - actual_diagnostics)
        missing_path_expectations = [
            _path_expectation_label(expectation)
            for expectation in expected_paths
            if not _path_expectation_matches(expectation, graph, findings)
        ]
        unexpected_incomplete = graph.coverage.incomplete != expect_incomplete
        total_tp += len(true_positive)
        total_fp += len(false_positive)
        total_fn += len(false_negative)
        results.append({
            "name": case["name"], "path": case["path"],
            "passed": (
                not false_positive
                and not false_negative
                and not missing_diagnostics
                and not missing_path_expectations
                and not unexpected_incomplete
            ),
            "true_positive": true_positive, "false_positive": false_positive,
            "false_negative": false_negative, "coverage": graph.coverage.as_dict(),
            "expected_diagnostics": expected_diagnostics,
            "missing_diagnostics": missing_diagnostics,
            "expected_paths": expected_paths,
            "missing_path_expectations": missing_path_expectations,
            "expect_incomplete": expect_incomplete,
        })
    precision = total_tp / (total_tp + total_fp) if total_tp + total_fp else 1.0
    recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 1.0
    per_rule: dict[str, dict[str, int | float | None]] = {}
    expected_by_rule = Counter(key.split("@", 1)[0] for case in results for key in case["true_positive"] + case["false_negative"])
    actual_by_rule = Counter(key.split("@", 1)[0] for case in results for key in case["true_positive"] + case["false_positive"])
    for rule_id in sorted(expected_by_rule.keys() | actual_by_rule.keys()):
        true_positive = sum(key.startswith(f"{rule_id}@") for case in results for key in case["true_positive"])
        false_positive = sum(key.startswith(f"{rule_id}@") for case in results for key in case["false_positive"])
        false_negative = sum(key.startswith(f"{rule_id}@") for case in results for key in case["false_negative"])
        per_rule[rule_id] = {
            "true_positives": true_positive, "false_positives": false_positive,
            "false_negatives": false_negative,
            "precision": true_positive / (true_positive + false_positive) if true_positive + false_positive else None,
            "recall": true_positive / (true_positive + false_negative) if true_positive + false_negative else None,
        }
    return {
        "version": 1, "manifest": str(manifest),
        "metrics": {
            "schema_version": 1, "cases_total": len(results),
            "cases_passed": sum(case["passed"] for case in results),
            "true_positives": total_tp, "false_positives": total_fp,
            "false_negatives": total_fn,
            "precision": precision if total_tp + total_fp else None,
            "recall": recall if total_tp + total_fn else None,
            "per_rule": per_rule,
        },
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
        "HorusTrace Reviewed Benchmark",
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
        if case["missing_diagnostics"]:
            lines.append("  Missing diagnostics: " + ", ".join(case["missing_diagnostics"]))
        if case["missing_path_expectations"]:
            lines.append(
                "  Missing path expectations: "
                + ", ".join(case["missing_path_expectations"])
            )
        if case["coverage"]["incomplete"]:
            lines.append("  Coverage incomplete")
    return "\n".join(lines).rstrip()


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2)
