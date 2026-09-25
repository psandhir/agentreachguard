from horustrace.authority_reconciliation import authority_reconciliation_report
from horustrace.deployment_evidence import (
    DeploymentEvidenceBundle,
    DeploymentWorkloadEvidence,
    IAMBindingEvidence,
)
from horustrace.models import Agent, Graph, Identity, Tool

IDENTITY = "support@prod.iam.gserviceaccount.com"


def _graph(*, roles: set[str], permissions: set[str]) -> Graph:
    identity = Identity(
        name=IDENTITY,
        provider="gcp",
        roles=set(roles),
        permissions=set(permissions),
        credential_source="workload_identity",
    )
    tool = Tool(
        name="tickets",
        kind="function",
        capabilities={"data.read"},
        identity=IDENTITY,
    )
    return Graph(
        agents=[
            Agent(
                name="support",
                tools=[tool],
                identities=[identity],
            )
        ]
    )


def _bundle(*bindings: IAMBindingEvidence) -> DeploymentEvidenceBundle:
    return DeploymentEvidenceBundle(
        provider="gcp",
        source="fixture",
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


def test_reconciliation_identifies_supported_excess_authority() -> None:
    graph = _graph(
        roles={"roles/viewer"},
        permissions={"tickets.read"},
    )
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/viewer",
            scope_kind="project",
            scope_name="prod",
            permissions=("tickets.read",),
        ),
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/storage.objectAdmin",
            scope_kind="project",
            scope_name="prod",
            permissions=("storage.objects.delete",),
        ),
    )

    agent = authority_reconciliation_report(graph, bundle)["agents"][0]

    assert agent["status"] == "excess_authority"
    assert agent["excess"]["roles"] == ["roles/storage.objectAdmin"]
    assert agent["excess"]["permissions"] == ["storage.objects.delete"]
    assert agent["missing"] == {"roles": [], "permissions": []}


def test_reconciliation_identifies_missing_required_authority() -> None:
    graph = _graph(
        roles={"roles/viewer"},
        permissions={"tickets.read", "tickets.write"},
    )
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/viewer",
            scope_kind="project",
            scope_name="prod",
            permissions=("tickets.read",),
        )
    )

    agent = authority_reconciliation_report(graph, bundle)["agents"][0]

    assert agent["status"] == "missing_authority"
    assert agent["missing"]["permissions"] == ["tickets.write"]


def test_missing_required_permission_evidence_does_not_create_false_excess() -> None:
    graph = _graph(roles={"roles/viewer"}, permissions=set())
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/viewer",
            scope_kind="project",
            scope_name="prod",
            permissions=("storage.objects.get",),
        )
    )

    agent = authority_reconciliation_report(graph, bundle)["agents"][0]

    assert agent["excess"]["permissions"] == []
    assert "required_permissions" in agent["unresolved"]
    assert agent["status"] == "unresolved"


def test_conditional_permissions_remain_unresolved_not_excess() -> None:
    graph = _graph(
        roles={"roles/viewer"},
        permissions={"tickets.read"},
    )
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/viewer",
            scope_kind="project",
            scope_name="prod",
            permissions=("tickets.read",),
        ),
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/storage.objectViewer",
            scope_kind="project",
            scope_name="prod",
            permissions=("storage.objects.get",),
            condition={"expression": "resource.name.startsWith('support-')"},
        ),
    )

    agent = authority_reconciliation_report(graph, bundle)["agents"][0]

    assert agent["deployed"]["conditional_roles"] == ["roles/storage.objectViewer"]
    assert agent["deployed"]["conditional_permissions"] == ["storage.objects.get"]
    assert "conditional_authority" in agent["unresolved"]
    assert agent["excess"]["roles"] == []
    assert agent["excess"]["permissions"] == []



def test_partial_required_role_evidence_can_prove_missing_authority() -> None:
    tool = Tool(
        name="connect_database",
        kind="function",
        capabilities={"data.read"},
        metadata={
            "required_authority_provider": "gcp",
            "required_roles": ["roles/cloudsql.client"],
            "required_roles_complete": False,
        },
    )
    graph = Graph(agents=[Agent(name="support", tools=[tool])])
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/storage.objectViewer",
            scope_kind="project",
            scope_name="prod",
        )
    )

    agent = authority_reconciliation_report(graph, bundle)["agents"][0]

    assert agent["status"] == "missing_authority"
    assert agent["missing"]["roles"] == ["roles/cloudsql.client"]
    assert agent["excess"]["roles"] == []
    assert "required_roles_incomplete" in agent["unresolved"]


def test_partial_required_roles_do_not_create_false_excess() -> None:
    tool = Tool(
        name="read_data",
        kind="function",
        capabilities={"data.read"},
        metadata={
            "required_authority_provider": "gcp",
            "required_roles": ["roles/bigquery.dataViewer"],
            "required_roles_complete": False,
        },
    )
    graph = Graph(agents=[Agent(name="support", tools=[tool])])
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/bigquery.dataEditor",
            scope_kind="project",
            scope_name="prod",
        ),
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/storage.objectAdmin",
            scope_kind="project",
            scope_name="prod",
        ),
    )

    agent = authority_reconciliation_report(graph, bundle)["agents"][0]

    # Data Editor satisfies the positive Data Viewer requirement, while the
    # incomplete baseline cannot prove Storage Object Admin is excess.
    assert agent["missing"]["roles"] == []
    assert agent["excess"]["roles"] == []
    assert agent["status"] == "unresolved"
    assert "required_roles_incomplete" in agent["unresolved"]
