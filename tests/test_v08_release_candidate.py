import json
from pathlib import Path

from horustrace.cli import main

IDENTITY = "support@prod.iam.gserviceaccount.com"


def _write_app(
    root: Path,
    *,
    required_permissions: tuple[str, ...] = ("tickets.read",),
) -> None:
    root.mkdir()
    permissions = ", ".join(required_permissions)
    (root / "horustrace.manifest.yaml").write_text(
        f"""
version: 1
identities:
  - name: {IDENTITY}
    provider: gcp
    roles: [roles/viewer]
    permissions: [{permissions}]
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
          permissions: [tickets.*]
        deny:
          iam_roles: [roles/owner]
          permissions: [secretmanager.*]
""",
        encoding="utf-8",
    )


def _write_snapshot(
    path: Path,
    *,
    include_excess: bool = False,
    include_conditional_secret: bool = False,
) -> None:
    bindings = [
        {
            "principal": IDENTITY,
            "role": "roles/viewer",
            "scope": {"kind": "project", "name": "prod"},
            "permissions": ["tickets.read"],
        }
    ]
    if include_excess:
        bindings.append(
            {
                "principal": IDENTITY,
                "role": "roles/storage.objectAdmin",
                "scope": {"kind": "project", "name": "prod"},
                "inherited_from": {"kind": "folder", "name": "12345"},
                "permissions": ["storage.objects.delete"],
            }
        )
    if include_conditional_secret:
        bindings.append(
            {
                "principal": IDENTITY,
                "role": "roles/secretmanager.secretAccessor",
                "scope": {"kind": "project", "name": "prod"},
                "permissions": ["secretmanager.versions.access"],
                "condition": {
                    "expression": (
                        "request.time < timestamp('2030-01-01T00:00:00Z')"
                    )
                },
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


def _run_json(*args: str) -> tuple[int, dict]:
    from contextlib import redirect_stdout
    from io import StringIO

    output = StringIO()
    with redirect_stdout(output):
        code = main(list(args))
    return code, json.loads(output.getvalue())


def test_release_candidate_adversarial_gcp_authority(tmp_path: Path) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "adversarial.json"
    _write_app(app)
    _write_snapshot(
        evidence,
        include_excess=True,
        include_conditional_secret=True,
    )

    code, report = _run_json(
        "reconcile",
        str(app),
        "--deployment-evidence",
        str(evidence),
        "--format",
        "json",
    )

    assert code == 0
    agent = report["reconciliation"]["agents"][0]
    assert agent["status"] == "excess_authority"
    assert agent["excess"]["roles"] == ["roles/storage.objectAdmin"]
    assert agent["excess"]["permissions"] == ["storage.objects.delete"]
    assert agent["deployed"]["conditional_roles"] == [
        "roles/secretmanager.secretAccessor"
    ]
    assert agent["deployed"]["conditional_permissions"] == [
        "secretmanager.versions.access"
    ]
    assert "conditional_authority" in agent["unresolved"]

    policy = report["deployed_policy"]["relationships"][0]
    assert policy["status"] == "violation"
    assert any(
        result["status"] == "unresolved"
        and result["dimension"] == "permissions"
        and result["observed"] == ["secretmanager.versions.access"]
        for result in policy["results"]
    )
    assert report["runtime_effectiveness"] == "not_verified"


def test_release_candidate_missing_required_permission(tmp_path: Path) -> None:
    app = tmp_path / "app"
    evidence = tmp_path / "missing.json"
    _write_app(app, required_permissions=("tickets.read", "tickets.write"))
    _write_snapshot(evidence)

    code, report = _run_json(
        "reconcile",
        str(app),
        "--deployment-evidence",
        str(evidence),
        "--format",
        "json",
    )

    assert code == 0
    agent = report["reconciliation"]["agents"][0]
    assert agent["status"] == "missing_authority"
    assert agent["missing"]["permissions"] == ["tickets.write"]
    assert agent["excess"]["permissions"] == []


def test_release_candidate_privilege_reduction_is_improvement(tmp_path: Path) -> None:
    app = tmp_path / "app"
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    _write_app(app)
    _write_snapshot(base, include_excess=True)
    _write_snapshot(head)

    code, report = _run_json(
        "reconcile",
        str(app),
        "--deployment-evidence",
        str(head),
        "--baseline-deployment-evidence",
        str(base),
        "--format",
        "json",
        "--fail-on-deployment-regression",
    )

    assert code == 0
    delta = report["deployment_delta"]
    assert delta["summary"]["regressed_agents"] == 0
    assert delta["summary"]["improved_agents"] == 1
    agent = delta["agents"][0]
    assert agent["excess"]["roles_resolved"] == ["roles/storage.objectAdmin"]
    assert agent["excess"]["permissions_resolved"] == ["storage.objects.delete"]
    assert agent["improved"] is True
