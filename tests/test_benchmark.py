import json
from pathlib import Path

import pytest
import yaml

from agentreachguard.benchmark import BenchmarkError, run
from agentreachguard.cli import main

REPOSITORY = Path(__file__).resolve().parents[1]


def test_reviewed_benchmark_has_perfect_current_metrics(capsys):
    manifest = REPOSITORY / "benchmarks" / "cases.yaml"
    report = run(manifest)
    assert report["summary"] == {
        "cases": 26, "passed": 26, "true_positive": 74,
        "false_positive": 0, "false_negative": 0,
        "precision": 1.0, "recall": 1.0,
    }
    incomplete = [case for case in report["cases"] if case["coverage"]["incomplete"]]
    assert [case["name"] for case in incomplete] == ["dynamic-tools-unresolved"]
    dynamic = incomplete[0]
    assert dynamic["expect_incomplete"] is True
    assert dynamic["expected_diagnostics"] == ["ARG-COV-004"]
    assert dynamic["missing_diagnostics"] == []

    assert main(["benchmark", str(manifest)]) == 0
    output = capsys.readouterr().out
    assert "26/26 passed" in output
    assert "Precision: 1.000" in output
    assert "Recall:    1.000" in output


def test_benchmark_reports_false_positive_and_negative(tmp_path: Path, capsys):
    case = tmp_path / "case"
    case.mkdir()
    (case / "agentreachguard.manifest.yaml").write_text('''
agents:
  - name: ops
    tools: [{name: shell, capabilities: [process.execute]}]
''')
    manifest = tmp_path / "cases.yaml"
    manifest.write_text('''
version: 1
cases:
  - name: deliberately-wrong-expectation
    path: case
    expected: [ADK999@ops]
''')
    report = run(manifest)
    assert report["summary"]["false_positive"] > 0
    assert report["summary"]["false_negative"] == 1
    assert report["summary"]["precision"] == 0.0
    assert report["summary"]["recall"] == 0.0
    assert main(["benchmark", str(manifest)]) == 1
    output = capsys.readouterr().out
    assert "Unexpected:" in output
    assert "Missing: ADK999@ops" in output


def test_benchmark_json_output(tmp_path: Path, capsys):
    manifest = REPOSITORY / "benchmarks" / "cases.yaml"
    assert main(["benchmark", str(manifest), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["precision"] == 1.0


@pytest.mark.parametrize("raw", [
    {}, {"version": 2, "cases": []}, {"version": True, "cases": []},
    {"version": 1, "cases": "bad"},
    {"version": 1, "cases": [{"name": "x", "path": "missing", "expected": []}]},
    {"version": 1, "cases": [{"name": "x", "path": ".", "expected": ["BAD"]}]},
])
def test_invalid_benchmark_manifest_fails_closed(tmp_path: Path, raw):
    path = tmp_path / "cases.yaml"
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(BenchmarkError):
        run(path)


def test_repository_scan_ignores_intentionally_vulnerable_benchmark_fixtures():
    from agentreachguard.scanner import scan

    graph, findings = scan(REPOSITORY, use_default_suppressions=False)
    locations = {str(f.location.path) for f in findings if f.location}
    assert not any("/benchmarks/" in location for location in locations)
    assert all("benchmarks" not in str(d.location.path) for d in graph.coverage.diagnostics
               if d.location)


def test_duplicate_benchmark_keys_fail_closed(tmp_path: Path):
    path = tmp_path / "cases.yaml"
    path.write_text("version: 1\nversion: 1\ncases: []\n")
    with pytest.raises(BenchmarkError):
        run(path)


def test_reviewed_corpus_has_at_least_25_cases() -> None:
    report = run(REPOSITORY / "benchmarks" / "cases.yaml")
    assert report["summary"]["cases"] >= 25
    assert report["summary"]["passed"] == report["summary"]["cases"]
    assert any(case["expect_incomplete"] for case in report["cases"])


def test_benchmark_reports_per_rule_metrics() -> None:
    report = run(REPOSITORY / "benchmarks" / "cases.yaml")
    metrics = report["metrics"]
    assert metrics["cases_total"] == 26
    assert metrics["per_rule"]["ADK004"]["true_positives"] > 0
    assert metrics["per_rule"]["ADK004"]["precision"] == 1.0
    assert metrics["per_rule"]["ADK002"]["true_positives"] == 1
    assert metrics["per_rule"]["AGT050"]["true_positives"] == 1
    assert metrics["per_rule"]["PATH005"]["true_positives"] == 1
