from pathlib import Path

from horustrace.scanner import scan


def test_sensitive_data_plus_external_write_is_critical(tmp_path: Path) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        """
version: 1
agents:
  - name: finance
    data:
      - name: board-pack
        classification: confidential
    tools:
      - name: send_email
        capability: external.write
        human_approval: false
""",
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    finding = next(f for f in findings if f.rule_id == "AGT010")
    assert finding.severity.name == "CRITICAL"


def test_approved_external_write_avoids_exfiltration_rule(tmp_path: Path) -> None:
    manifest = tmp_path / "horustrace.manifest.yaml"
    manifest.write_text(
        """
version: 1
agents:
  - name: finance
    data:
      - name: board-pack
        classification: confidential
    tools:
      - name: send_email
        capability: external.write
        human_approval: true
        guardrails: true
""",
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    assert not any(f.rule_id == "AGT010" for f in findings)
