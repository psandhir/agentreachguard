import json
from pathlib import Path

from agentreachguard.cli import main


def test_disabled_rule_is_not_reported_as_suppressed(tmp_path: Path, capsys) -> None:
    (tmp_path / "agent.py").write_text(
        "from agents import Agent, ShellTool\n"
        "agent = Agent(name='ops', tools=[ShellTool()])\n",
        encoding="utf-8",
    )
    (tmp_path / ".agentreachguard.yaml").write_text(
        "version: 1\nrules:\n  AGT020: {enabled: false}\n",
        encoding="utf-8",
    )
    (tmp_path / ".agentreachguard.suppressions.yaml").write_text(
        "version: 1\nsuppressions:\n"
        "  - id: old-shell-exception\n"
        "    reason: no longer needed because repository policy disables this rule\n"
        "    expires: 2099-01-01\n"
        "    rule_id: AGT020\n"
        "    agent: ops\n",
        encoding="utf-8",
    )

    assert main(["scan", str(tmp_path), "--format", "json", "--fail-on", "none"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert "AGT020" in report["configuration"]["disabled_rules"]
    assert not any(item["rule_id"] == "AGT020" for item in report["findings"])
    assert not any(item["rule_id"] == "AGT020" for item in report["suppressions"]["suppressed_findings"])
    diagnostic = next(
        item for item in report["suppressions"]["diagnostics"]
        if item["id"] == "old-shell-exception"
    )
    assert diagnostic["status"] == "stale"
    assert diagnostic["matches"] == 0
