from horustrace.deployment_delta import deployment_authority_delta
from horustrace.deployment_evidence import (
    DeploymentEvidenceBundle,
    DeploymentWorkloadEvidence,
    IAMBindingEvidence,
)
from horustrace.models import Agent, Graph, Identity, Tool

IDENTITY = "support@prod.iam.gserviceaccount.com"


def _graph() -> Graph:
    identity = Identity(
        name=IDENTITY,
        provider="gcp",
        roles={"roles/viewer"},
        permissions={"tickets.read"},
        credential_source="workload_identity",
    )
    return Graph(
        agents=[
            Agent(
                name="support",
                identities=[identity],
                tools=[
                    Tool(
                        name="tickets",
                        kind="function",
                        capabilities={"data.read"},
                        identity=IDENTITY,
                    )
                ],
            )
        ]
    )


def _bundle(source: str, *bindings: IAMBindingEvidence) -> DeploymentEvidenceBundle:
    return DeploymentEvidenceBundle(
        provider="gcp",
        source=source,
        workloads=(
            DeploymentWorkloadEvidence(
                workload_id="projects/prod/locations/europe-west1/services/support",
                kind="cloud_run",
                name="support",
                identity=IDENTITY,
                agent="support",
            ),
        ),
        iam_bindings=tuple(bindings),
    )


def _viewer() -> IAMBindingEvidence:
    return IAMBindingEvidence(
        principal=IDENTITY,
        role="roles/viewer",
        scope_kind="project",
        scope_name="prod",
        permissions=("tickets.read",),
    )


def test_delta_identifies_new_agent_excess_authority() -> None:
    base = _bundle("base", _viewer())
    head = _bundle(
        "head",
        _viewer(),
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/secretmanager.secretAccessor",
            scope_kind="project",
            scope_name="prod",
            permissions=("secretmanager.versions.access",),
        ),
    )

    delta = deployment_authority_delta(_graph(), base, head)
    agent = delta["agents"][0]

    assert delta["summary"]["regressed_agents"] == 1
    assert agent["excess"]["roles_introduced"] == [
        "roles/secretmanager.secretAccessor"
    ]
    assert agent["excess"]["permissions_introduced"] == [
        "secretmanager.versions.access"
    ]
    assert agent["trust_boundary_crossings"] == ["secret_access"]
    assert agent["regressed"] is True


def test_delta_identifies_resolved_excess_authority() -> None:
    base = _bundle(
        "base",
        _viewer(),
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/storage.objectAdmin",
            scope_kind="project",
            scope_name="prod",
            permissions=("storage.objects.delete",),
        ),
    )
    head = _bundle("head", _viewer())

    delta = deployment_authority_delta(_graph(), base, head)
    agent = delta["agents"][0]

    assert agent["excess"]["roles_resolved"] == ["roles/storage.objectAdmin"]
    assert agent["excess"]["permissions_resolved"] == ["storage.objects.delete"]
    assert agent["improved"] is True
    assert delta["summary"]["improved_agents"] == 1


def test_delta_tracks_new_uncertainty_as_regression() -> None:
    base = _bundle("base", _viewer())
    head = _bundle(
        "head",
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/viewer",
            scope_kind="project",
            scope_name="prod",
        ),
    )

    delta = deployment_authority_delta(_graph(), base, head)
    agent = delta["agents"][0]

    assert "permissions" in agent["unresolved"]["introduced"]
    assert agent["regressed"] is True

def test_delta_tracks_conditional_authority_changes_even_when_unresolved_persists() -> None:
    base = _bundle(
        "base",
        _viewer(),
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/storage.objectViewer",
            scope_kind="project",
            scope_name="prod",
            permissions=("storage.objects.get",),
            condition={"expression": "resource.name.startsWith('support-')"},
        ),
    )
    head = _bundle(
        "head",
        _viewer(),
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/secretmanager.secretAccessor",
            scope_kind="project",
            scope_name="prod",
            permissions=("secretmanager.versions.access",),
            condition={"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"},
        ),
    )

    delta = deployment_authority_delta(_graph(), base, head)
    agent = delta["agents"][0]

    assert agent["conditional"]["roles_added"] == [
        "roles/secretmanager.secretAccessor"
    ]
    assert agent["conditional"]["roles_removed"] == ["roles/storage.objectViewer"]
    assert agent["conditional"]["permissions_added"] == [
        "secretmanager.versions.access"
    ]
    assert agent["trust_boundary_crossings"] == ["secret_access"]
    assert agent["regressed"] is True

