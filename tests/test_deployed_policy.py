from horustrace.deployed_policy import deployed_policy_report
from horustrace.deployment_evidence import (
    DeploymentEvidenceBundle,
    DeploymentWorkloadEvidence,
    IAMBindingEvidence,
)
from horustrace.models import (
    Agent,
    AgentPolicy,
    AuthorityContract,
    AuthorityScope,
    Graph,
    Identity,
    Tool,
)

IDENTITY = "support@prod.iam.gserviceaccount.com"


def _graph(contract: AuthorityContract | None) -> Graph:
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
                policy=AgentPolicy(authority=contract),
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


def test_deployed_denied_role_is_contract_violation() -> None:
    contract = AuthorityContract(
        deny=AuthorityScope(iam_roles={"roles/owner"}),
    )
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/owner",
            scope_kind="project",
            scope_name="prod",
            permissions=("resourcemanager.projects.setIamPolicy",),
        )
    )

    evaluation = deployed_policy_report(_graph(contract), bundle)["relationships"][0]

    assert evaluation["status"] == "violation"
    assert evaluation["results"][0]["clause"] == "deny.iam_roles"
    assert evaluation["results"][0]["observed"] == ["roles/owner"]


def test_deployed_permission_outside_allowlist_is_violation() -> None:
    contract = AuthorityContract(
        allow=AuthorityScope(permissions={"tickets.*"}),
    )
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="projects/prod/roles/support",
            scope_kind="project",
            scope_name="prod",
            permissions=("tickets.read", "storage.objects.delete"),
        )
    )

    evaluation = deployed_policy_report(_graph(contract), bundle)["relationships"][0]

    assert evaluation["status"] == "violation"
    result = evaluation["results"][0]
    assert result["clause"] == "allow.permissions"
    assert result["observed"] == ["storage.objects.delete"]


def test_conditional_policy_conflict_is_unresolved_not_violation() -> None:
    contract = AuthorityContract(
        deny=AuthorityScope(permissions={"secretmanager.*"}),
    )
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/secretmanager.secretAccessor",
            scope_kind="project",
            scope_name="prod",
            permissions=("secretmanager.versions.access",),
            condition={"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"},
        )
    )

    evaluation = deployed_policy_report(_graph(contract), bundle)["relationships"][0]

    assert evaluation["status"] == "unresolved"
    assert evaluation["results"][0]["status"] == "unresolved"
    assert evaluation["results"][0]["conditional"] is True


def test_missing_authority_contract_is_reported_not_silently_compliant() -> None:
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/viewer",
            scope_kind="project",
            scope_name="prod",
            permissions=("tickets.read",),
        )
    )

    evaluation = deployed_policy_report(_graph(None), bundle)["relationships"][0]

    assert evaluation["status"] == "not_configured"
    assert evaluation["results"] == []

def test_conditional_denied_role_is_unresolved_not_violation() -> None:
    contract = AuthorityContract(
        deny=AuthorityScope(iam_roles={"roles/owner"}),
    )
    bundle = _bundle(
        IAMBindingEvidence(
            principal=IDENTITY,
            role="roles/owner",
            scope_kind="project",
            scope_name="prod",
            permissions=("resourcemanager.projects.setIamPolicy",),
            condition={"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"},
        )
    )

    evaluation = deployed_policy_report(_graph(contract), bundle)["relationships"][0]

    assert evaluation["status"] == "unresolved"
    role_result = next(
        result
        for result in evaluation["results"]
        if result["dimension"] == "iam_roles"
    )
    assert role_result["status"] == "unresolved"
    assert role_result["observed"] == ["roles/owner"]
    assert role_result["conditional"] is True

