import json
from pathlib import Path

from horustrace import cli
from horustrace.cli import main
from horustrace.rule_registry import iter_rule_metadata


def test_rules_console_lists_every_registered_rule_once(capsys) -> None:
    assert main(["rules"]) == 0
    output = capsys.readouterr().out
    for rule in iter_rule_metadata():
        assert output.count(rule.rule_id) == 1


def test_rules_json_is_parseable_deterministic_and_ordered(capsys) -> None:
    assert main(["rules", "--format", "json"]) == 0
    first = capsys.readouterr().out
    assert main(["rules", "--format", "json"]) == 0
    second = capsys.readouterr().out
    assert first == second
    report = json.loads(first)
    assert report["schema_version"] == 1
    assert [item["rule_id"] for item in report["rules"]] == [
        rule.rule_id for rule in iter_rule_metadata()
    ]
    assert set(report["rules"][0]) == {
        "rule_id", "layer", "title", "default_severity", "category", "assessment",
        "rationale", "remediation", "references", "owasp_agentic",
    }


def test_rules_output_writes_file_without_stdout(tmp_path: Path, capsys) -> None:
    output = tmp_path / "rules.json"
    assert main(["rules", "--format", "json", "--output", str(output)]) == 0
    assert capsys.readouterr().out == ""
    assert json.loads(output.read_text())["schema_version"] == 1


def test_rules_does_not_scan_or_require_a_repository(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)

    def fail_if_scanned(*args, **kwargs):
        raise AssertionError("rules must not scan")

    monkeypatch.setattr(cli, "scan", fail_if_scanned)
    assert main(["rules"]) == 0
    assert "AGT001" in capsys.readouterr().out


def test_rules_rejects_unknown_format(capsys) -> None:
    assert main(["rules", "--format", "sarif"]) == 1
    assert "console, json" in capsys.readouterr().err
