from pathlib import Path

from horustrace.models import Finding, Severity, SourceLocation
from horustrace.reporters.sarif import render


def test_sarif_contains_rule_and_location() -> None:
    finding = Finding(
        rule_id="AGT999",
        severity=Severity.HIGH,
        title="Test",
        message="Example",
        recommendation="Fix it",
        location=SourceLocation(Path("agent.py"), 4, 2),
    )
    sarif = render([finding])
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "AGT999"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 4
