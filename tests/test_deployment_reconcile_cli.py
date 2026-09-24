import json
from pathlib import Path

from horustrace.cli import main

IDENTITY = "support@prod.iam.gserviceaccount.com"


def _write_app(root: Path) -> None:
    root.mkdir()
    (root / "horustrace.manifest.yaml").write_text(
        f"""
version: 1
identities:
  - name: {IDENTITY}
    provider: gcp
    roles: [roles/viewer]
    permissions: [tickets.read]
    credential_source: workload_identity
agents:
  - name: support
    identities: [{IDENTITY}]
    tools:
      - name: tickets
        kind: function
        capabilities: [data.read]
        identity: {IDENTITY}
        approval: true
        resources:
          - kind: ticket
            selector: support/*
            access: [data.read]
        destinations: [https://support.example.test]
    policy:
      authority:
        allow:
          identities: [{IDENTITY}]
          iam_roles: [roles/viewer]
          permissions: [tickets.read]
""",
        encoding="utf-8",
    )


def _write_evidence(path: Path, *, excess: bool = False) -> None:
    bindings = [
        {
            "principal": IDENTITY,
            "role": "roles/viewer",
            "scope": {"kind": "project", "name": "prod"},
            "permissions": ["tickets.read"],
        }
    ]
    if excess:
        bindings.append(
            {
                "principal": IDENTITY,
                "role": "roles/storage.objectAdmin",
                "scope": {"kind": "project", "name": "prod"},
                "permissions": ["storage.objects.delete"],
            }
        )
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "provider": "gcp",
                "source": path.name,
                "workloads": [
                    {
                        "workload_id": (
                            "projects/prod/locations/europe-west1/services/support"
                        ),
                        "kind": "cloud_run",
                        "name": "support",
                        "identity": IDENTITY,
                        "agent": "support",
                        "project": "prod",
                        "region": "europe-west1",
                    }
                ],
                "iam_bindings": bindings,
            }
        ),
        encoding="utf-8",
    )


def test_reconcile_cli_reports_aligned_deployment(tmp_path: Path, capsys) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "deployment.json"
    _write_app(app)
    _write_evidence(evidence)

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(evidence),
            "--format",
            "json",
        ]
    ) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["excess_authority_agents"] == 0
    assert report["summary"]["deployed_policy_violations"] == 0
    assert report["reconciliation"]["agents"][0]["status"] == "aligned"


def test_reconcile_cli_can_fail_on_supported_excess_authority(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "deployment.json"
    _write_app(app)
    _write_evidence(evidence, excess=True)

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(evidence),
            "--format",
            "json",
            "--fail-on-excess-authority",
        ]
    ) == 2

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["excess_authority_agents"] == 1
    agent = report["reconciliation"]["agents"][0]
    assert agent["excess"]["roles"] == ["roles/storage.objectAdmin"]
    assert agent["excess"]["permissions"] == ["storage.objects.delete"]


def test_reconcile_cli_can_fail_on_deployed_contract_violation(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "deployment.json"
    _write_app(app)
    _write_evidence(evidence, excess=True)

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(evidence),
            "--format",
            "json",
            "--fail-on-deployed-policy-violation",
        ]
    ) == 2

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["deployed_policy_violations"] == 1


def test_reconcile_cli_can_fail_on_deployment_authority_regression(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    baseline = tmp_path / "baseline.json"
    head = tmp_path / "head.json"
    _write_app(app)
    _write_evidence(baseline)
    _write_evidence(head, excess=True)

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(head),
            "--baseline-deployment-evidence",
            str(baseline),
            "--format",
            "json",
            "--fail-on-deployment-regression",
        ]
    ) == 2

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["deployment_regressed_agents"] == 1
    delta = report["deployment_delta"]["agents"][0]
    assert delta["excess"]["permissions_introduced"] == ["storage.objects.delete"]


def test_deployment_regression_gate_requires_baseline(
    tmp_path: Path,
    capsys,
) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "deployment.json"
    _write_app(app)
    _write_evidence(evidence)

    assert main(
        [
            "reconcile",
            str(app),
            "--deployment-evidence",
            str(evidence),
            "--fail-on-deployment-regression",
        ]
    ) == 1

    assert "requires --baseline-deployment-evidence" in capsys.readouterr().err
