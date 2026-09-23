import json
from pathlib import Path

from horustrace.cli import main
from horustrace.owasp import build_owasp_agentic_summary


def _category(report: dict, risk_id: str) -> dict:
    return next(item for item in report["categories"] if item["id"] == risk_id)


def test_owasp_summary_distinguishes_findings_no_findings_and_not_assessed(
    tmp_path: Path,
    capsys,
) -> None:
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, ShellTool\n"
        "agent = Agent(name='ops', tools=[ShellTool()])\n",
        encoding="utf-8",
    )

    assert main(["owasp", str(tmp_path), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["standard"] == "OWASP Top 10 for Agentic Applications 2026"
    assert _category(report, "ASI05")["status"] == "finding"
    assert "AGT020" in _category(report, "ASI05")["finding_rule_ids"]
    assert _category(report, "ASI06")["status"] == "no_mapped_findings"
    assert "PATH007" in _category(report, "ASI06")["mapped_rules"]
    assert _category(report, "ASI08")["status"] == "not_assessed"
    assert _category(report, "ASI09")["status"] == "not_assessed"
    assert _category(report, "ASI10")["status"] == "not_assessed"


def test_owasp_summary_treats_fully_disabled_category_as_not_assessed() -> None:
    report = build_owasp_agentic_summary([], disabled_rules=["AGT050"])
    asi04 = _category(report, "ASI04")

    assert asi04["status"] == "not_assessed"
    assert asi04["mapped_rules"] == []
    assert asi04["disabled_mapped_rules"] == ["AGT050"]
    assert asi04["available_mapped_rules"] == ["AGT050"]


def test_scan_json_includes_owasp_summary(tmp_path: Path, capsys) -> None:
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, ShellTool\n"
        "agent = Agent(name='ops', tools=[ShellTool()])\n",
        encoding="utf-8",
    )

    assert main(["scan", str(tmp_path), "--format", "json", "--fail-on", "none"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["owasp_agentic"]["summary"]["categories"] == 10
    assert _category(report["owasp_agentic"], "ASI05")["status"] == "finding"


def test_scan_console_shows_owasp_mapping_on_finding(tmp_path: Path, capsys) -> None:
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, ShellTool\n"
        "agent = Agent(name='ops', tools=[ShellTool()])\n",
        encoding="utf-8",
    )

    assert main(["scan", str(tmp_path), "--fail-on", "none"]) == 0
    output = capsys.readouterr().out

    assert "OWASP Agentic: ASI05" in output


def test_sarif_run_properties_include_owasp_summary(tmp_path: Path, capsys) -> None:
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, ShellTool\n"
        "agent = Agent(name='ops', tools=[ShellTool()])\n",
        encoding="utf-8",
    )

    assert main(["scan", str(tmp_path), "--format", "sarif", "--fail-on", "none"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    report = sarif["runs"][0]["properties"]["owasp_agentic"]

    assert _category(report, "ASI05")["status"] == "finding"
    assert _category(report, "ASI08")["status"] == "not_assessed"
