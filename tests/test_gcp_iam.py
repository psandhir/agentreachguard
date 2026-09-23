from __future__ import annotations

import json
from pathlib import Path

import pytest

from horustrace.cli import main
from horustrace.gcp_iam import (
    GcpIamSnapshotError,
    enrich_gcp_iam_snapshot,
    load_gcp_iam_snapshot,
)
from horustrace.models import Agent, Graph, Identity
from horustrace.rules.builtin import evaluate


_AGENT_SA = "agent@demo-project.iam.gserviceaccount.com"
_OTHER_SA = "other@demo-project.iam.gserviceaccount.com"


def _snapshot_records() -> list[dict]:
    return [
        {
            "resource": "//cloudresourcemanager.googleapis.com/projects/demo-project",
            "assetType": "cloudresourcemanager.googleapis.com/Project",
            "policy": {
                "bindings": [
                    {
                        "role": "roles/owner",
                        "members": [
                            f"serviceAccount:{_AGENT_SA}",
                            "user:operator@example.test",
                        ],
                    },
                    {
                        "role": "roles/viewer",
                        "members": [f"serviceAccount:{_OTHER_SA}"],
                    },
                ]
            },
        },
        {
            "resource": "//storage.googleapis.com/demo-sensitive-bucket",
            "assetType": "storage.googleapis.com/Bucket",
            "policy": {
                "bindings": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": [f"serviceAccount:{_AGENT_SA}"],
                        "condition": {
                            "title": "temporary",
                            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
                        },
                    }
                ]
            },
        },
    ]


def _write_snapshot(path: Path, raw: object | None = None) -> Path:
    path.write_text(
        json.dumps(_snapshot_records() if raw is None else raw),
        encoding="utf-8",
    )
    return path


def test_load_gcloud_search_all_iam_policies_json(tmp_path: Path) -> None:
    path = _write_snapshot(tmp_path / "iam.json")

    snapshot = load_gcp_iam_snapshot(path)

    assert snapshot.result_count == 2
    assert len(snapshot.grants) == 3
    assert snapshot.service_account_principals == {_AGENT_SA, _OTHER_SA}
    agent_grants = [grant for grant in snapshot.grants if grant.principal == _AGENT_SA]
    assert {grant.role for grant in agent_grants} == {
        "roles/owner",
        "roles/storage.objectViewer",
    }
    assert sum(grant.conditional for grant in agent_grants) == 1


def test_load_rest_results_object(tmp_path: Path) -> None:
    path = _write_snapshot(
        tmp_path / "iam-rest.json",
        {"results": _snapshot_records()},
    )

    snapshot = load_gcp_iam_snapshot(path)

    assert snapshot.result_count == 2
    assert len(snapshot.grants) == 3


def test_invalid_snapshot_fails_closed(tmp_path: Path) -> None:
    path = _write_snapshot(
        tmp_path / "invalid.json",
        [{"resource": "//example", "policy": {"bindings": "not-a-list"}}],
    )

    with pytest.raises(GcpIamSnapshotError, match="bindings must be a list"):
        load_gcp_iam_snapshot(path)


def test_enrichment_only_updates_known_service_accounts(tmp_path: Path) -> None:
    path = _write_snapshot(tmp_path / "iam.json")
    identity = Identity(name=_AGENT_SA, provider="gcp")
    graph = Graph(
        agents=[Agent(name="analyst", identities=[identity])],
        identities=[],
    )

    summary = enrich_gcp_iam_snapshot(graph, path)

    assert identity.roles == {"roles/owner", "roles/storage.objectViewer"}
    assert identity.resource_scope is None
    assert identity.metadata["gcp_iam_resources"] == [
        "//cloudresourcemanager.googleapis.com/projects/demo-project",
        "//storage.googleapis.com/demo-sensitive-bucket",
    ]
    assert identity.metadata["gcp_iam_conditional_grants"] == 1
    assert len(identity.metadata["gcp_iam_grants"]) == 2
    assert len(identity.provenance) == 2
    assert all(fact.origin == "observed" for fact in identity.provenance)
    assert summary["matched_identities"] == 1
    assert summary["matched_grants"] == 2
    assert summary["unmatched_service_account_principals"] == 1
    assert len(graph.all_identities()) == 1


def test_enrichment_promotes_matching_generic_service_account_to_gcp(
    tmp_path: Path,
) -> None:
    path = _write_snapshot(
        tmp_path / "iam.json",
        [_snapshot_records()[0]],
    )
    identity = Identity(
        name=f"projects/-/serviceAccounts/{_AGENT_SA}",
        provider="generic",
    )
    graph = Graph(agents=[Agent(name="analyst", identities=[identity])])

    summary = enrich_gcp_iam_snapshot(graph, path)

    assert identity.provider == "gcp"
    assert identity.roles == {"roles/owner"}
    assert identity.resource_scope == (
        "//cloudresourcemanager.googleapis.com/projects/demo-project"
    )
    assert summary["matched_identities"] == 1


def _write_manifest(path: Path) -> None:
    path.write_text(
        f"""version: 1
agents:
  - name: cloud-analyst
    identities:
      - name: {_AGENT_SA}
        provider: gcp
        credential_source: workload_identity
    tools: []
""",
        encoding="utf-8",
    )


def test_scan_cli_enriches_identity_and_reports_cloud_admin_role(
    tmp_path: Path,
    capsys,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write_manifest(project / "horustrace.manifest.yaml")
    snapshot = _write_snapshot(tmp_path / "gcp-iam.json")

    result = main(
        [
            "scan",
            str(project),
            "--gcp-iam-snapshot",
            str(snapshot),
            "--format",
            "json",
            "--fail-on",
            "none",
        ]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    enrichment = report["coverage"]["resolution"]["gcp_iam"]
    assert enrichment["matched_identities"] == 1
    assert enrichment["matched_grants"] == 2
    finding = next(
        item
        for item in report["findings"]
        if item["rule_id"] == "IDN001" and item["agent"] == "cloud-analyst"
    )
    assert finding["severity"] == "high"
    assert "roles=roles/owner" in finding["evidence"]
    assert any(
        fact["origin"] == "observed"
        and "gcp_iam_role=roles/owner" in fact["fact"]
        for fact in finding["provenance"]
    )
    assert finding["limitations"] == []


def test_conditional_admin_role_is_reported_with_condition_limitation(
    tmp_path: Path,
) -> None:
    snapshot = _write_snapshot(
        tmp_path / "conditional-admin.json",
        [
            {
                "resource": "//cloudresourcemanager.googleapis.com/projects/demo-project",
                "assetType": "cloudresourcemanager.googleapis.com/Project",
                "policy": {
                    "bindings": [
                        {
                            "role": "roles/owner",
                            "members": [f"serviceAccount:{_AGENT_SA}"],
                            "condition": {
                                "title": "temporary-owner",
                                "expression": (
                                    "request.time < timestamp('2030-01-01T00:00:00Z')"
                                ),
                            },
                        }
                    ]
                },
            }
        ],
    )
    identity = Identity(name=_AGENT_SA, provider="gcp")
    graph = Graph(agents=[Agent(name="analyst", identities=[identity])])

    enrich_gcp_iam_snapshot(graph, snapshot)
    finding = next(item for item in evaluate(graph) if item.rule_id == "IDN001")

    assert "conditional_roles=roles/owner" in finding.evidence
    assert finding.limitations == [
        "The triggering GCP IAM admin role is conditional; "
        "IAM condition expressions were not evaluated."
    ]


def test_graph_cli_exposes_observed_cloud_resource_scopes(
    tmp_path: Path,
    capsys,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write_manifest(project / "horustrace.manifest.yaml")
    snapshot = _write_snapshot(tmp_path / "gcp-iam.json")

    result = main(
        [
            "graph",
            str(project),
            "--gcp-iam-snapshot",
            str(snapshot),
        ]
    )

    assert result == 0
    graph = json.loads(capsys.readouterr().out)
    identity = next(
        node
        for node in graph["nodes"]
        if node["kind"] == "identity" and node["name"] == _AGENT_SA
    )
    assert identity["attributes"]["authority_source"] == "gcp_iam_snapshot"
    assert identity["attributes"]["roles"] == [
        "roles/owner",
        "roles/storage.objectViewer",
    ]
    assert identity["attributes"]["resource_scopes"] == [
        "//cloudresourcemanager.googleapis.com/projects/demo-project",
        "//storage.googleapis.com/demo-sensitive-bucket",
    ]
    assert identity["attributes"]["conditional_grants"] == 1
