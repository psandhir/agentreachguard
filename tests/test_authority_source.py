import json
from pathlib import Path

from horustrace.authority_source import enrich_from_terraform_authority_source
from horustrace.adapters.iac_identity import scan_terraform
from horustrace.cli import main
from horustrace.models import Agent, Graph, Identity
from horustrace.scanner import scan


SERVICE_ACCOUNT = "support-agent@prod-project.iam.gserviceaccount.com"
OTHER_SERVICE_ACCOUNT = "other-agent@prod-project.iam.gserviceaccount.com"


def _write_authority_repo(root: Path) -> None:
    root.mkdir()
    (root / "main.tf").write_text(
        f"""
resource "google_project_iam_binding" "support_admin" {{
  project = "prod-project"
  role    = "roles/owner"
  members = [
    "serviceAccount:{SERVICE_ACCOUNT}",
    "serviceAccount:{OTHER_SERVICE_ACCOUNT}",
  ]
}}
""",
        encoding="utf-8",
    )


def _write_application_manifest(root: Path) -> None:
    root.mkdir()
    (root / "horustrace.manifest.yaml").write_text(
        f"""
identities:
  - name: {SERVICE_ACCOUNT}
    provider: gcp
agents:
  - name: support-agent
    identities:
      - {SERVICE_ACCOUNT}
""",
        encoding="utf-8",
    )


def test_terraform_binding_members_are_normalized_as_individual_identities(
    tmp_path: Path,
) -> None:
    terraform = tmp_path / "iam.tf"
    terraform.write_text(
        f"""
resource "google_project_iam_binding" "support" {{
  project = "prod-project"
  role    = "roles/viewer"
  members = [
    "serviceAccount:{SERVICE_ACCOUNT}",
    "serviceAccount:{OTHER_SERVICE_ACCOUNT}",
  ]
}}
""",
        encoding="utf-8",
    )

    graph = scan_terraform(terraform)

    assert {identity.name for identity in graph.identities} == {
        f"serviceAccount:{SERVICE_ACCOUNT}",
        f"serviceAccount:{OTHER_SERVICE_ACCOUNT}",
    }
    assert all(identity.roles == {"roles/viewer"} for identity in graph.identities)
    assert all(identity.resource_scope == "prod-project" for identity in graph.identities)


def test_authority_source_enriches_only_already_discovered_service_accounts(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "infra"
    _write_authority_repo(authority)
    identity = Identity(name=SERVICE_ACCOUNT, provider="generic")
    graph = Graph(agents=[Agent(name="support-agent", identities=[identity])])

    result = enrich_from_terraform_authority_source(graph, authority)

    assert identity.provider == "gcp"
    assert identity.roles == {"roles/owner"}
    assert identity.resource_scope == "prod-project"
    assert result.matched_identities == 1
    assert result.matched_bindings == 1
    assert result.unmatched_service_accounts == 1
    assert [item.name for item in graph.all_identities()] == [SERVICE_ACCOUNT]

    declared = identity.metadata["declared_authority"]
    assert declared["state"] == "declared"
    assert declared["kind"] == "terraform"
    assert declared["source"] == "infra"
    assert declared["bindings"][0]["path"] == "infra/main.tf"
    assert declared["bindings"][0]["roles"] == ["roles/owner"]
    assert identity.provenance[0].origin == "terraform_authority_source"


def test_multiple_declared_scopes_are_retained_without_collapsing_scalar_scope(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "infra"
    authority.mkdir()
    (authority / "iam.tf").write_text(
        f"""
resource "google_project_iam_member" "project_access" {{
  project = "prod-project"
  role    = "roles/viewer"
  member  = "serviceAccount:{SERVICE_ACCOUNT}"
}}

resource "google_folder_iam_member" "folder_access" {{
  folder = "123456789"
  role   = "roles/storage.admin"
  member = "serviceAccount:{SERVICE_ACCOUNT}"
}}
""",
        encoding="utf-8",
    )
    identity = Identity(name=SERVICE_ACCOUNT, provider="gcp")
    graph = Graph(agents=[Agent(name="support-agent", identities=[identity])])

    enrich_from_terraform_authority_source(graph, authority)

    assert identity.roles == {"roles/viewer", "roles/storage.admin"}
    assert identity.resource_scope is None
    bindings = identity.metadata["declared_authority"]["bindings"]
    assert {binding["resource_scope"] for binding in bindings} == {
        "prod-project",
        "123456789",
    }


def test_scan_uses_declared_terraform_authority_for_layer3_findings(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    authority = tmp_path / "infra"
    _write_application_manifest(app)
    _write_authority_repo(authority)

    graph, findings = scan(app, authority_source=authority)

    idn001 = [finding for finding in findings if finding.rule_id == "IDN001"]
    assert len(idn001) == 1
    assert idn001[0].agent == "support-agent"
    assert "roles=roles/owner" in idn001[0].evidence
    assert graph.coverage.resolution["authority_source"]["state"] == "declared"
    assert graph.coverage.resolution["authority_source"]["matched_identities"] == 1

    adg = graph.adg.as_dict()
    identity_nodes = [
        node
        for node in adg["nodes"]
        if node["kind"] == "identity" and node["label"] == SERVICE_ACCOUNT
    ]
    assert identity_nodes
    assert identity_nodes[0]["attributes"]["declared_authority"]["state"] == "declared"


def test_scan_cli_accepts_authority_source(tmp_path: Path, capsys) -> None:
    app = tmp_path / "app"
    authority = tmp_path / "infra"
    _write_application_manifest(app)
    _write_authority_repo(authority)

    assert main(
        [
            "scan",
            str(app),
            "--authority-source",
            str(authority),
            "--format",
            "json",
            "--fail-on",
            "none",
        ]
    ) == 0

    report = json.loads(capsys.readouterr().out)
    authority_resolution = report["coverage"]["resolution"]["authority_source"]
    assert authority_resolution["kind"] == "terraform"
    assert authority_resolution["state"] == "declared"
    assert authority_resolution["matched_identities"] == 1
    assert authority_resolution["unmatched_service_accounts"] == 1
