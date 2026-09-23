from __future__ import annotations

import json
from pathlib import Path

import pytest

from horustrace.cli import main
from horustrace.gcp_iam import (
    GcpIamExportError,
    enrich_graph_with_gcp_iam_export,
    load_gcp_iam_export,
)
from horustrace.models import Agent, Graph, Identity
from horustrace.scanner import scan


def _write_export(path: Path) -> Path:
    records = [
        {
            "name": "//cloudresourcemanager.googleapis.com/projects/example",
            "assetType": "cloudresourcemanager.googleapis.com/Project",
            "ancestors": ["projects/123", "folders/456", "organizations/789"],
            "iamPolicy": {
                "bindings": [
                    {
                        "role": "roles/owner",
                        "members": [
                            "serviceAccount:agent-sa@example.iam.gserviceaccount.com",
                            "user:owner@example.com",
                        ],
                    }
                ]
            },
        },
        {
            "name": "//storage.googleapis.com/example-sensitive",
            "assetType": "storage.googleapis.com/Bucket",
            "ancestors": ["projects/123", "organizations/789"],
            "iamPolicy": {
                "bindings": [
                    {
                        "role": "roles/storage.admin",
                        "members": [
                            "serviceAccount:agent-sa@example.iam.gserviceaccount.com"
                        ],
                        "condition": {
                            "title": "limited-window",
                            "description": "Temporary administrative access",
                            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
                        },
                    }
                ]
            },
        },
        {
            "name": "//cloudresourcemanager.googleapis.com/projects/example",
            "assetType": "cloudresourcemanager.googleapis.com/Project",
            "ancestors": ["projects/123", "folders/456", "organizations/789"],
            "iamPolicy": {
                "bindings": [
                    {
                        "role": "roles/owner",
                        "members": [
                            "serviceAccount:agent-sa@example.iam.gserviceaccount.com"
                        ],
                    }
                ]
            },
        },
    ]
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )
    return path


def _write_manifest(path: Path, *, provider: str = "gcp") -> Path:
    path.write_text(
        f"""version: 1
agents:
  - name: cloud-agent
    identities:
      - name: agent-sa@example.iam.gserviceaccount.com
        provider: {provider}
""",
        encoding="utf-8",
    )
    return path


def test_load_gcp_iam_export_filters_service_accounts_and_preserves_condition(
    tmp_path: Path,
) -> None:
    export = _write_export(tmp_path / "iam.ndjson")

    bindings, records = load_gcp_iam_export(export)

    assert records == 3
    assert len(bindings) == 3
    assert all(
        item.principal
        == "serviceAccount:agent-sa@example.iam.gserviceaccount.com"
        for item in bindings
    )
    conditional = next(item for item in bindings if item.conditional)
    assert conditional.role == "roles/storage.admin"
    assert conditional.resource == "//storage.googleapis.com/example-sensitive"
    assert conditional.asset_type == "storage.googleapis.com/Bucket"
    assert conditional.ancestors == ("projects/123", "organizations/789")
    assert conditional.condition == {
        "title": "limited-window",
        "description": "Temporary administrative access",
        "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
    }


def test_gcp_iam_enrichment_is_exact_deduped_and_condition_aware(
    tmp_path: Path,
) -> None:
    export = _write_export(tmp_path / "iam.ndjson")
    identity = Identity(
        name="serviceAccount:agent-sa@example.iam.gserviceaccount.com",
        provider="gcp",
    )
    graph = Graph(agents=[Agent(name="cloud-agent", identities=[identity])])

    summary = enrich_graph_with_gcp_iam_export(graph, export)

    assert summary.records == 3
    assert summary.service_account_bindings == 3
    assert summary.matched_identities == 1
    assert summary.matched_bindings == 2
    assert summary.conditional_matched_bindings == 1
    assert identity.roles == {"roles/owner"}
    assert identity.resource_scope == (
        "//cloudresourcemanager.googleapis.com/projects/example"
    )
    assert identity.metadata["gcp_iam_evidence_source"] == (
        "cloud_asset_inventory_export"
    )
    assert len(identity.metadata["gcp_iam_bindings"]) == 2
    assert {
        fact.fact for fact in identity.provenance
    } == {
        "gcp_iam_role=roles/owner@"
        "//cloudresourcemanager.googleapis.com/projects/example",
        "gcp_iam_conditional_role=roles/storage.admin@"
        "//storage.googleapis.com/example-sensitive",
    }


def test_gcp_iam_enrichment_does_not_match_generic_identity(tmp_path: Path) -> None:
    export = _write_export(tmp_path / "iam.ndjson")
    identity = Identity(
        name="agent-sa@example.iam.gserviceaccount.com",
        provider="generic",
    )
    graph = Graph(agents=[Agent(name="cloud-agent", identities=[identity])])

    summary = enrich_graph_with_gcp_iam_export(graph, export)

    assert summary.matched_identities == 0
    assert identity.roles == set()
    assert "gcp_iam_bindings" not in identity.metadata


def test_gcp_iam_export_rejects_malformed_binding_condition(tmp_path: Path) -> None:
    export = tmp_path / "bad.ndjson"
    export.write_text(
        json.dumps(
            {
                "name": "//cloudresourcemanager.googleapis.com/projects/example",
                "iamPolicy": {
                    "bindings": [
                        {
                            "role": "roles/viewer",
                            "members": [
                                "serviceAccount:agent-sa@example.iam.gserviceaccount.com"
                            ],
                            "condition": {"expression": 42},
                        }
                    ]
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(GcpIamExportError, match=r"condition\.expression"):
        load_gcp_iam_export(export)


def test_scan_gcp_iam_export_enriches_adg_and_identity_findings(
    tmp_path: Path,
) -> None:
    manifest = _write_manifest(tmp_path / "horustrace.manifest.yaml")
    export = _write_export(tmp_path / "iam.ndjson")

    graph, findings = scan(tmp_path, gcp_iam_export=export)

    identity = graph.agents[0].identities[0]
    assert identity.roles == {"roles/owner"}
    assert any(
        finding.rule_id == "IDN001" and finding.agent == "cloud-agent"
        for finding in findings
    )
    assert graph.configuration_audit["gcp_iam_export"] == {
        "path": export.as_posix(),
        "records": 3,
        "service_account_bindings": 3,
        "matched_identities": 1,
        "matched_bindings": 2,
        "conditional_matched_bindings": 1,
    }

    assert graph.adg is not None
    identity_node = next(
        node
        for node in graph.adg.nodes
        if node.kind == "identity"
        and node.name == "agent-sa@example.iam.gserviceaccount.com"
    )
    assert identity_node.attributes["roles"] == ["roles/owner"]
    assert identity_node.attributes["resource_scope"] == (
        "//cloudresourcemanager.googleapis.com/projects/example"
    )
    assert len(identity_node.attributes["gcp_iam_bindings"]) == 2
    conditional = next(
        item
        for item in identity_node.attributes["gcp_iam_bindings"]
        if item["conditional"]
    )
    assert conditional["role"] == "roles/storage.admin"

    assert manifest.exists()


def test_scan_cli_reports_gcp_iam_enrichment_audit(tmp_path: Path, capsys) -> None:
    _write_manifest(tmp_path / "horustrace.manifest.yaml")
    export = _write_export(tmp_path / "iam.ndjson")

    result = main(
        [
            "scan",
            str(tmp_path),
            "--gcp-iam-export",
            str(export),
            "--format",
            "json",
            "--fail-on",
            "none",
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["enrichment"]["gcp_iam_export"]["matched_identities"] == 1
    assert report["enrichment"]["gcp_iam_export"]["matched_bindings"] == 2
    assert any(item["rule_id"] == "IDN001" for item in report["findings"])


def test_graph_cli_accepts_gcp_iam_export(tmp_path: Path, capsys) -> None:
    _write_manifest(tmp_path / "horustrace.manifest.yaml")
    export = _write_export(tmp_path / "iam.ndjson")

    result = main(
        [
            "graph",
            str(tmp_path),
            "--gcp-iam-export",
            str(export),
        ]
    )

    assert result == 0
    graph = json.loads(capsys.readouterr().out)
    identity = next(
        item
        for item in graph["nodes"]
        if item["kind"] == "identity"
        and item["name"] == "agent-sa@example.iam.gserviceaccount.com"
    )
    assert identity["attributes"]["roles"] == ["roles/owner"]
    assert len(identity["attributes"]["gcp_iam_bindings"]) == 2


def test_conditional_admin_binding_does_not_become_unconditional_role(
    tmp_path: Path,
) -> None:
    _write_manifest(tmp_path / "horustrace.manifest.yaml")
    export = tmp_path / "conditional.ndjson"
    export.write_text(
        json.dumps(
            {
                "name": "//cloudresourcemanager.googleapis.com/projects/example",
                "assetType": "cloudresourcemanager.googleapis.com/Project",
                "iamPolicy": {
                    "bindings": [
                        {
                            "role": "roles/owner",
                            "members": [
                                "serviceAccount:agent-sa@example.iam.gserviceaccount.com"
                            ],
                            "condition": {
                                "title": "break-glass-window",
                                "expression": (
                                    "request.time < "
                                    "timestamp('2030-01-01T00:00:00Z')"
                                ),
                            },
                        }
                    ]
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path, gcp_iam_export=export)

    identity = graph.agents[0].identities[0]
    assert identity.roles == set()
    assert not any(finding.rule_id == "IDN001" for finding in findings)
    assert len(identity.metadata["gcp_iam_bindings"]) == 1
    assert identity.metadata["gcp_iam_bindings"][0]["conditional"] is True


def test_default_scan_preserves_identity_adg_attribute_shape(tmp_path: Path) -> None:
    _write_manifest(tmp_path / "horustrace.manifest.yaml")

    graph, _ = scan(tmp_path)

    assert graph.adg is not None
    identity_node = next(
        node for node in graph.adg.nodes if node.kind == "identity"
    )
    assert set(identity_node.attributes) == {
        "provider",
        "roles",
        "permissions",
        "oauth_scopes",
        "credential_source",
    }

