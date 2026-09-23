import json
from pathlib import Path

from horustrace.cli import main
from horustrace.rule_registry import OWASP_AGENTIC_IDS, RULE_REGISTRY


def test_owasp_mapping_identifiers_are_valid() -> None:
    assert all(
        set(metadata.owasp_agentic) <= OWASP_AGENTIC_IDS
        for metadata in RULE_REGISTRY.values()
    )


def test_required_initial_owasp_mappings_are_present() -> None:
    assert RULE_REGISTRY["PATH001"].owasp_agentic == ("ASI01", "ASI05")
    assert all(RULE_REGISTRY[rule_id].owasp_agentic == ("ASI03",) for rule_id in (
        "IDN001", "IDN002", "IDN003", "IDN004",
    ))
    assert RULE_REGISTRY["AGT050"].owasp_agentic == ("ASI04",)
    assert RULE_REGISTRY["PATH007"].owasp_agentic == ("ASI06",)
    assert all("ASI05" in RULE_REGISTRY[rule_id].owasp_agentic for rule_id in (
        "AGT020", "ADK002", "ADK004", "ADK012",
    ))


def test_scan_json_and_sarif_report_owasp_mappings(tmp_path: Path, capsys) -> None:
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, ShellTool\nagent = Agent(name='ops', tools=[ShellTool()])\n",
        encoding="utf-8",
    )
    assert main(["scan", str(tmp_path), "--format", "json", "--fail-on", "none"]) == 0
    report = json.loads(capsys.readouterr().out)
    finding = next(item for item in report["findings"] if item["rule_id"] == "AGT020")
    assert finding["standards"] == {"owasp_agentic": ["ASI05"]}

    assert main(["scan", str(tmp_path), "--format", "sarif", "--fail-on", "none"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    result = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "AGT020")
    assert result["properties"]["standards"] == {"owasp_agentic": ["ASI05"]}
    rule = next(item for item in sarif["runs"][0]["tool"]["driver"]["rules"] if item["id"] == "AGT020")
    assert rule["properties"]["standards"] == {"owasp_agentic": ["ASI05"]}
