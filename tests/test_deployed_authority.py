from horustrace.deployed_authority import deployed_authority_report
from horustrace.deployment_evidence import (
    DeploymentEvidenceBundle,
    DeploymentWorkloadEvidence,
    IAMBindingEvidence,
)
from horustrace.models import Agent, Graph

IDENTITY = "support-agent@prod.iam.gserviceaccount.com"


def _graph() -> Graph:
    return Graph(agents=[Agent(name="support")])


def _workload() -> DeploymentWorkloadEvidence:
    return DeploymentWorkloadEvidence(
        workload_id="projects/prod/locations/europe-west1/services/support",
        kind="cloud_run",
        name="support",
        identity=IDENTITY,
        agent="support",
        project="prod",
    )


def test_deployed_authority_expands_inherited_gcp_role_permissions() -> None:
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=(_workload(),),
        iam_bindings=(
            IAMBindingEvidence(
                principal=f"serviceAccount:{IDENTITY}",
                role="roles/secretmanager.secretAccessor",
                scope_kind="project",
                scope_name="prod",
                inherited_from_kind="folder",
                inherited_from_name="12345",
            ),
        ),
        role_permissions={
            "roles/secretmanager.secretAccessor": (
                "secretmanager.versions.access",
                "secretmanager.versions.get",
            )
        },
    )

    relationship = deployed_authority_report(_graph(), bundle)["relationships"][0]

    assert relationship["roles"] == ["roles/secretmanager.secretAccessor"]
    assert relationship["permissions"] == [
        "secretmanager.versions.access",
        "secretmanager.versions.get",
    ]
    assert relationship["inherited_from"] == [{"kind": "folder", "name": "12345"}]
    assert relationship["resolution"] == "fully_resolved"


def test_inline_binding_permissions_are_retained_without_role_catalogue() -> None:
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=(_workload(),),
        iam_bindings=(
            IAMBindingEvidence(
                principal=IDENTITY,
                role="projects/prod/roles/customAgent",
                scope_kind="project",
                scope_name="prod",
                permissions=("tickets.read", "tickets.write"),
            ),
        ),
    )

    relationship = deployed_authority_report(_graph(), bundle)["relationships"][0]

    assert relationship["permissions"] == ["tickets.read", "tickets.write"]
    assert relationship["unresolved_roles"] == []
    assert "permissions" not in relationship["unresolved"]


def test_conditioned_binding_does_not_become_unconditional_authority() -> None:
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=(_workload(),),
        iam_bindings=(
            IAMBindingEvidence(
                principal=IDENTITY,
                role="roles/storage.objectAdmin",
                scope_kind="project",
                scope_name="prod",
                condition={"expression": "resource.name.startsWith('projects/_/buckets/support-')"},
            ),
        ),
        role_permissions={
            "roles/storage.objectAdmin": (
                "storage.objects.create",
                "storage.objects.delete",
            )
        },
    )

    relationship = deployed_authority_report(_graph(), bundle)["relationships"][0]

    assert relationship["roles"] == []
    assert relationship["conditional_roles"] == ["roles/storage.objectAdmin"]
    assert relationship["permissions"] == []
    assert relationship["conditional_permissions"] == [
        "storage.objects.create",
        "storage.objects.delete",
    ]
    assert relationship["resolution"] == "partially_resolved"
    assert "iam_condition_applicability" in relationship["unresolved"]


def test_unknown_role_permission_expansion_stays_unresolved() -> None:
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=(_workload(),),
        iam_bindings=(
            IAMBindingEvidence(
                principal=IDENTITY,
                role="roles/custom.unknown",
                scope_kind="project",
                scope_name="prod",
            ),
        ),
    )

    relationship = deployed_authority_report(_graph(), bundle)["relationships"][0]

    assert relationship["unresolved_roles"] == ["roles/custom.unknown"]
    assert "permissions" in relationship["unresolved"]


def test_unrelated_principal_is_not_attached_to_agent() -> None:
    bundle = DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
        workloads=(_workload(),),
        iam_bindings=(
            IAMBindingEvidence(
                principal="other@prod.iam.gserviceaccount.com",
                role="roles/owner",
                scope_kind="project",
                scope_name="prod",
                permissions=("resourcemanager.projects.setIamPolicy",),
            ),
        ),
    )

    relationship = deployed_authority_report(_graph(), bundle)["relationships"][0]

    assert relationship["roles"] == []
    assert relationship["permissions"] == []
    assert "iam_bindings" in relationship["unresolved"]
