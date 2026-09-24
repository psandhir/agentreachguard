import json
from pathlib import Path

import pytest

from horustrace.deployment_evidence import (
    DeploymentEvidenceError,
    load_deployment_evidence,
)


def _document() -> dict:
    return {
        "schema_version": 1,
        "provider": "gcp",
        "source": "cloud-asset-export",
        "workloads": [
            {
                "workload_id": "projects/prod/locations/europe-west1/services/support-agent",
                "kind": "cloud_run",
                "name": "support-agent",
                "identity": "support-agent@prod.iam.gserviceaccount.com",
                "agent": "support",
                "project": "prod",
                "region": "europe-west1",
            }
        ],
        "iam_bindings": [
            {
                "principal": "serviceAccount:support-agent@prod.iam.gserviceaccount.com",
                "role": "roles/secretmanager.secretAccessor",
                "scope": {"kind": "project", "name": "prod"},
                "inherited_from": {"kind": "folder", "name": "12345"},
                "condition": {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"},
            }
        ],
        "role_permissions": {
            "roles/secretmanager.secretAccessor": [
                "secretmanager.versions.get",
                "secretmanager.versions.access",
            ]
        },
    }


def test_json_deployment_evidence_is_normalized(tmp_path: Path) -> None:
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps(_document()), encoding="utf-8")

    bundle = load_deployment_evidence(path)
    document = bundle.as_dict()

    assert document["schema_version"] == 1
    assert document["provider"] == "gcp"
    assert document["workloads"][0]["agent"] == "support"
    assert document["workloads"][0]["identity"].endswith(".gserviceaccount.com")
    binding = document["iam_bindings"][0]
    assert binding["inherited"] is True
    assert binding["inherited_from"] == {"kind": "folder", "name": "12345"}
    assert binding["condition"]["expression"].startswith("request.time")
    assert document["role_permissions"]["roles/secretmanager.secretAccessor"] == [
        "secretmanager.versions.access",
        "secretmanager.versions.get",
    ]


def test_yaml_deployment_evidence_is_supported(tmp_path: Path) -> None:
    path = tmp_path / "deployment.yaml"
    path.write_text(
        """
schema_version: 1
provider: gcp
workloads:
  - workload_id: projects/prod/locations/europe-west1/services/support-agent
    kind: cloud_run
    name: support-agent
    identity: support-agent@prod.iam.gserviceaccount.com
iam_bindings: []
role_permissions: {}
""",
        encoding="utf-8",
    )

    bundle = load_deployment_evidence(path)

    assert bundle.source == "deployment.yaml"
    assert bundle.workloads[0].kind == "cloud_run"
    assert bundle.iam_bindings == ()


@pytest.mark.parametrize(
    "mutation, message",
    [
        ({"schema_version": 2}, "schema_version"),
        ({"unexpected": True}, "unsupported field"),
        ({"workloads": {}}, "workloads must be a list"),
        ({"iam_bindings": {}}, "iam_bindings must be a list"),
    ],
)
def test_invalid_deployment_evidence_fails_closed(
    tmp_path: Path,
    mutation: dict,
    message: str,
) -> None:
    document = _document()
    document.update(mutation)
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(DeploymentEvidenceError, match=message):
        load_deployment_evidence(path)


def test_unknown_nested_workload_field_fails_closed(tmp_path: Path) -> None:
    document = _document()
    document["workloads"][0]["service_account"] = "shadow@example.test"
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(DeploymentEvidenceError, match="unsupported field"):
        load_deployment_evidence(path)
