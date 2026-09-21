from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from horustrace.cli import main
from horustrace.scanner import scan
from horustrace.suppressions import SuppressionError


def vulnerable_project(root: Path, padding: str = "") -> None:
    (root / "agent.py").write_text(f'''{padding}
from agents import Agent, ShellTool
agent = Agent(name="ops", tools=[ShellTool()])
''', encoding="utf-8")


def future(days: int = 30) -> str:
    return (datetime.now(tz=UTC).date() + timedelta(days=days)).isoformat()


def write_suppressions(root: Path, items: list[dict]) -> Path:
    path = root / ".horustrace.suppressions.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "suppressions": items}, sort_keys=False))
    return path


def test_fingerprint_is_stable_across_line_moves_and_checkout_roots(tmp_path: Path):
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    vulnerable_project(one)
    vulnerable_project(two, "\n\n")
    first = {f.rule_id: f.fingerprint for f in scan(one)[1]}
    second = {f.rule_id: f.fingerprint for f in scan(two)[1]}
    assert first == second
    assert all(value.startswith("arg-v1:") for value in first.values())


def test_fingerprint_suppression_is_applied_and_audited(tmp_path: Path):
    vulnerable_project(tmp_path)
    _, initial = scan(tmp_path)
    target = next(f for f in initial if f.rule_id == "AGT020")
    write_suppressions(tmp_path, [{
        "id": "accepted-shell", "reason": "Temporary migration tool; owner SEC-12",
        "expires": future(), "fingerprint": target.fingerprint, "rule_id": "AGT020",
    }])
    graph, findings = scan(tmp_path)
    assert not any(f.rule_id == "AGT020" for f in findings)
    assert [f.rule_id for f in graph.suppressed_findings] == ["AGT020"]
    assert graph.suppression_diagnostics == [{
        "id": "accepted-shell", "status": "matched", "matches": 1,
        "expires": future(), "reason": "Temporary migration tool; owner SEC-12",
    }]


def test_yaml_date_value_is_supported(tmp_path: Path):
    vulnerable_project(tmp_path)
    target = next(f for f in scan(tmp_path)[1] if f.rule_id == "AGT020")
    path = tmp_path / ".horustrace.suppressions.yaml"
    path.write_text(f'''version: 1
suppressions:
  - id: documented-form
    reason: Matches the documented natural YAML date
    expires: 2099-12-31
    fingerprint: {target.fingerprint}
''')
    graph, findings = scan(tmp_path)
    assert not any(f.rule_id == "AGT020" for f in findings)
    assert graph.suppression_diagnostics[0]["expires"] == "2099-12-31"


def test_scoped_rule_suppression_does_not_hide_another_agent(tmp_path: Path):
    (tmp_path / "horustrace.manifest.yaml").write_text('''
agents:
  - name: a
    tools: [{name: shell, capabilities: [process.execute]}]
  - name: b
    tools: [{name: shell, capabilities: [process.execute]}]
''')
    write_suppressions(tmp_path, [{
        "id": "agent-a", "reason": "Accepted only for isolated agent a",
        "expires": future(), "rule_id": "AGT020", "agent": "a",
    }])
    graph, findings = scan(tmp_path)
    assert not any(f.rule_id == "AGT020" and f.agent == "a" for f in findings)
    assert any(f.rule_id == "AGT020" and f.agent == "b" for f in findings)
    assert len(graph.suppressed_findings) == 1


def test_path_glob_scope_matches_relative_paths(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    vulnerable_project(project)
    write_suppressions(project, [{
        "id": "legacy-path", "reason": "Legacy fixture pending deletion",
        "expires": future(), "rule_id": "AGT020", "path": "agent.py",
    }])
    _, findings = scan(project)
    assert not any(f.rule_id == "AGT020" for f in findings)


def test_expired_and_stale_suppressions_remain_visible(tmp_path: Path, capsys):
    vulnerable_project(tmp_path)
    write_suppressions(tmp_path, [
        {"id": "expired", "reason": "Old exception", "expires": "2000-01-01",
         "rule_id": "AGT020", "agent": "ops"},
        {"id": "stale", "reason": "Finding was fixed", "expires": future(),
         "rule_id": "ADK999", "agent": "ops"},
    ])
    graph, findings = scan(tmp_path)
    assert any(f.rule_id == "AGT020" for f in findings)
    assert {d["status"] for d in graph.suppression_diagnostics} == {"expired", "stale"}
    assert main(["scan", str(tmp_path), "--strict", "--fail-on", "none"]) == 1
    output = capsys.readouterr().out
    assert "expired" in output and "stale" in output


@pytest.mark.parametrize("item", [
    {"id": "x", "reason": "why", "expires": "bad", "rule_id": "AGT020", "agent": "a"},
    {"id": "x", "reason": "why", "expires": "2099-01-01", "rule_id": "AGT020"},
    {"id": "x", "reason": "", "expires": "2099-01-01", "fingerprint": "arg-v1:x"},
    {"id": "x", "reason": "why", "expires": "2099-01-01"},
    {"id": "x", "reason": "why", "expires": "2099-01-01", "fingerprint": "arg-v1:x",
     "unknown": True},
    {"id": "bad id", "reason": "why", "expires": "2099-01-01",
     "fingerprint": "arg-v1:0123456789abcdef01234567"},
    {"id": "x", "reason": "line one\nline two", "expires": "2099-01-01",
     "fingerprint": "arg-v1:0123456789abcdef01234567"},
    {"id": "x", "reason": "why", "expires": "2099-01-01",
     "rule_id": "AGT020", "path": "../outside.py"},
])
def test_invalid_suppressions_fail_closed(tmp_path: Path, item):
    vulnerable_project(tmp_path)
    write_suppressions(tmp_path, [item])
    with pytest.raises(SuppressionError):
        scan(tmp_path)


def test_boolean_suppression_version_is_rejected(tmp_path: Path):
    vulnerable_project(tmp_path)
    (tmp_path / ".horustrace.suppressions.yaml").write_text(
        "version: true\nsuppressions: []\n"
    )
    with pytest.raises(SuppressionError):
        scan(tmp_path)


def test_explicit_missing_suppression_file_fails(tmp_path: Path):
    vulnerable_project(tmp_path)
    with pytest.raises(SuppressionError, match="does not exist"):
        scan(tmp_path, suppressions_path=tmp_path / "missing.yaml")


def test_baseline_command_writes_expiring_fingerprints(tmp_path: Path, capsys):
    vulnerable_project(tmp_path)
    output = tmp_path / "baseline.yaml"
    assert main([
        "baseline", str(tmp_path), "--output", str(output),
        "--reason", "Initial adoption backlog SEC-42", "--expires", future(),
    ]) == 0
    raw = yaml.safe_load(output.read_text())
    assert raw["version"] == 1
    assert raw["suppressions"]
    assert all(item["fingerprint"].startswith("arg-v1:") for item in raw["suppressions"])
    assert all(item["reason"] == "Initial adoption backlog SEC-42" for item in raw["suppressions"])
    assert "Wrote" in capsys.readouterr().out


def test_baseline_ignores_an_existing_default_suppression(tmp_path: Path):
    vulnerable_project(tmp_path)
    initial = scan(tmp_path)[1]
    write_suppressions(tmp_path, [{
        "id": "old", "reason": "Existing exception", "expires": future(),
        "fingerprint": initial[0].fingerprint,
    }])
    output = tmp_path / "new-baseline.yaml"
    assert main(["baseline", str(tmp_path), "--output", str(output),
                 "--reason", "Full current state", "--expires", future()]) == 0
    assert len(yaml.safe_load(output.read_text())["suppressions"]) == len(initial)


def test_baseline_rejects_past_expiry(tmp_path: Path, capsys):
    vulnerable_project(tmp_path)
    assert main(["baseline", str(tmp_path), "--reason", "bad",
                 "--expires", "2000-01-01"]) == 1
    assert "must not be in the past" in capsys.readouterr().err


def test_baseline_does_not_replace_existing_file_without_force(tmp_path: Path, capsys):
    vulnerable_project(tmp_path)
    output = tmp_path / "baseline.yaml"
    output.write_text("keep-me")
    args = ["baseline", str(tmp_path), "--output", str(output),
            "--reason", "Adoption", "--expires", future()]
    assert main(args) == 1
    assert output.read_text() == "keep-me"
    assert "use --force" in capsys.readouterr().err
    assert main([*args, "--force"]) == 0
    assert yaml.safe_load(output.read_text())["version"] == 1


def test_duplicate_yaml_keys_fail_closed(tmp_path: Path):
    vulnerable_project(tmp_path)
    path = tmp_path / ".horustrace.suppressions.yaml"
    path.write_text("version: 1\nversion: 1\nsuppressions: []\n")
    with pytest.raises(SuppressionError):
        scan(tmp_path)


@pytest.mark.parametrize("output_format", ["json", "sarif"])
def test_machine_reports_include_fingerprints_and_suppression_audit(
    tmp_path: Path, capsys, output_format,
):
    vulnerable_project(tmp_path)
    target = next(f for f in scan(tmp_path)[1] if f.rule_id == "AGT020")
    write_suppressions(tmp_path, [{
        "id": "audit", "reason": "Reviewed exception SEC-9", "expires": future(),
        "fingerprint": target.fingerprint,
    }])
    assert main(["scan", str(tmp_path), "--format", output_format,
                 "--fail-on", "none"]) == 0
    report = __import__("json").loads(capsys.readouterr().out)
    if output_format == "json":
        audit = report["suppressions"]
        active = report["findings"]
        suppressed = audit["suppressed_findings"]
    else:
        run = report["runs"][0]
        audit = run["properties"]["suppressions"]
        active = run["results"]
        suppressed = audit["suppressed_findings"]
        assert all("partialFingerprints" in result for result in active)
    assert not any((item.get("rule_id") or item.get("ruleId")) == "AGT020" for item in active)
    assert suppressed[0]["fingerprint"].startswith("arg-v1:")
    assert audit["diagnostics"][0]["reason"] == "Reviewed exception SEC-9"


def test_multiple_default_suppression_files_are_rejected(tmp_path: Path):
    vulnerable_project(tmp_path)
    for suffix in ("yaml", "yml"):
        (tmp_path / f".horustrace.suppressions.{suffix}").write_text(
            "version: 1\nsuppressions: []\n"
        )
    with pytest.raises(SuppressionError, match="multiple default"):
        scan(tmp_path)


def test_baseline_rejects_blank_reason(tmp_path: Path, capsys):
    vulnerable_project(tmp_path)
    assert main(["baseline", str(tmp_path), "--reason", "   ",
                 "--expires", future()]) == 1
    assert "must not be blank" in capsys.readouterr().err


def test_baseline_refuses_incomplete_analysis(tmp_path: Path, capsys):
    (tmp_path / "agent.py").write_text("from agents import Agent\nAgent(")
    output = tmp_path / "baseline.yaml"
    assert main(["baseline", str(tmp_path), "--output", str(output),
                 "--reason", "Adoption", "--expires", future()]) == 1
    assert "analysis is incomplete" in capsys.readouterr().err
    assert not output.exists()
