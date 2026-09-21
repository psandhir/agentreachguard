import json
from pathlib import Path

from horustrace.cli import main
from horustrace.models import Confidence
from horustrace.scanner import scan
from horustrace.suppressions import fingerprint


def _all_path_project(root: Path) -> None:
    (root / "horustrace.manifest.yaml").write_text(
        """
agents:
  - name: ops
    inputs: [{name: web, trust: untrusted}]
    data: [{name: records, classification: confidential}]
    tools:
      - {name: shell, capabilities: [process.execute]}
      - {name: delete, capabilities: [destructive.write]}
      - {name: secrets, capabilities: [secrets.read]}
      - {name: publish, capabilities: [external.write]}
""",
        encoding="utf-8",
    )


def test_all_path_findings_have_potential_confidence(tmp_path: Path) -> None:
    _all_path_project(tmp_path)
    _, findings = scan(tmp_path)
    paths = [finding for finding in findings if finding.rule_id.startswith("PATH")]
    assert {finding.rule_id for finding in paths} == {
        "PATH001", "PATH002", "PATH003", "PATH004", "PATH005", "PATH006",
    }
    assert all(finding.confidence is Confidence.POTENTIAL for finding in paths)
    assert not any(
        finding.confidence in {Confidence.AUTHORITY_CONFIRMED, Confidence.RUNTIME_VERIFIED}
        for finding in paths
    )


def test_confidence_does_not_change_existing_fingerprint(tmp_path: Path) -> None:
    _all_path_project(tmp_path)
    _, findings = scan(tmp_path)
    finding = next(item for item in findings if item.rule_id == "PATH001")
    original = fingerprint(finding, tmp_path)
    finding.confidence = Confidence.SUPPORTED
    assert fingerprint(finding, tmp_path) == original


def test_path_confidence_is_reported_in_console_json_and_sarif(tmp_path: Path, capsys) -> None:
    _all_path_project(tmp_path)
    assert main(["scan", str(tmp_path), "--format", "console", "--fail-on", "none"]) == 0
    assert "Confidence: potential" in capsys.readouterr().out

    assert main(["scan", str(tmp_path), "--format", "json", "--fail-on", "none"]) == 0
    report = json.loads(capsys.readouterr().out)
    finding = next(item for item in report["findings"] if item["rule_id"] == "PATH001")
    assert finding["confidence"] == "potential"

    assert main(["scan", str(tmp_path), "--format", "sarif", "--fail-on", "none"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    result = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "PATH001")
    assert result["properties"]["confidence"] == "potential"
