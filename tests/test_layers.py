from pathlib import Path

from horustrace.scanner import scan


def _scan_manifest(tmp_path: Path, text: str):
    (tmp_path / "horustrace.manifest.yaml").write_text(text, encoding="utf-8")
    return scan(tmp_path)


def test_layer_2_capability_budget_detects_excess(tmp_path: Path) -> None:
    _, findings = _scan_manifest(
        tmp_path,
        """
agents:
  - name: analyst
    policy:
      required: [data.read]
    tools:
      - name: send_email
        capability: external.write
        human_approval: true
""",
    )
    finding = next(f for f in findings if f.rule_id == "CAP001")
    assert finding.layer == 2
    assert "external.write" in finding.evidence[1]


def test_layer_3_identity_detects_admin_and_wildcard(tmp_path: Path) -> None:
    _, findings = _scan_manifest(
        tmp_path,
        """
identities:
  - name: agent-sa
    provider: gcp
    roles: [roles/owner]
    permissions: ['*']
""",
    )
    ids = {f.rule_id for f in findings}
    assert "IDN001" in ids
    assert "IDN002" in ids
    assert all(f.layer == 3 for f in findings if f.rule_id.startswith("IDN"))


def test_layer_4_reachability_detects_sensitive_data_and_open_egress(tmp_path: Path) -> None:
    _, findings = _scan_manifest(
        tmp_path,
        """
agents:
  - name: finance
    data:
      - name: board
        classification: confidential
        selector: /finance/**
    network:
      - target: '*'
        restricted: false
    tools:
      - name: upload_report
        capability: external.write
        human_approval: false
""",
    )
    ids = {f.rule_id for f in findings}
    assert "NET001" in ids
    assert "DATA003" in ids
    assert "AGT010" in ids


def test_layer_4_explicit_unrestricted_destination_remains_flagged(
    tmp_path: Path,
) -> None:
    _, findings = _scan_manifest(
        tmp_path,
        """
agents:
  - name: publisher
    network:
      - target: https://api.example.com/events
        restricted: false
    tools:
      - name: publish
        capability: external.write
        human_approval: true
""",
    )

    assert any(f.rule_id == "NET001" for f in findings)


def test_layer_5_attack_path_untrusted_input_to_shell(tmp_path: Path) -> None:
    _, findings = _scan_manifest(
        tmp_path,
        """
agents:
  - name: web-ops
    inputs:
      - name: web-page
        kind: web
        trust: untrusted
    tools:
      - name: shell_exec
        capability: process.execute
        human_approval: false
""",
    )
    path = next(f for f in findings if f.rule_id == "PATH001")
    assert path.layer == 5
    assert "web-page -> web-ops -> shell_exec -> process.execute" in path.evidence[0]


def test_policy_resource_and_destination_allowlists(tmp_path: Path) -> None:
    _, findings = _scan_manifest(
        tmp_path,
        """
agents:
  - name: scoped
    policy:
      allowed_resources: ['/approved/**']
      allowed_destinations: ['https://api.example.com/**']
    tools:
      - name: upload
        capability: external.write
        human_approval: true
        resources:
          - kind: file
            selector: /other/file.txt
        destinations:
          - https://evil.example.test/upload
""",
    )
    ids = {f.rule_id for f in findings}
    assert "DATA002" in ids
    assert "NET003" in ids


def test_terraform_identity_layer(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        '''resource "google_project_iam_member" "agent" {
  project = "prod-project"
  role    = "roles/owner"
  member  = "serviceAccount:agent@example.iam.gserviceaccount.com"
}
''',
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    assert any(i.provider == "gcp" for i in graph.identities)
    assert any(f.rule_id == "IDN001" for f in findings)
