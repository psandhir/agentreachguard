from dataclasses import replace
from pathlib import Path

from horustrace.effective_authority import effective_authority_relationships
from horustrace.models import (
    Agent,
    Graph,
    Identity,
    MCPServer,
    NetworkDestination,
    SourceLocation,
    Tool,
)
from horustrace.trust_boundaries import (
    classify_boundary_crossings,
    classify_relationship,
    trust_boundary_report,
)


def _tool_relationship(
    root: Path,
    *,
    capabilities: set[str],
    approval: bool | None = None,
    guardrails: bool = False,
    identity: Identity | None = None,
    semantics: dict | None = None,
    destinations: list[NetworkDestination] | None = None,
):
    location = SourceLocation(root / "agent.py", line=7)
    tool = Tool(
        name="action",
        kind="function",
        capabilities=capabilities,
        approval=approval,
        guardrails=guardrails,
        identity=identity.name if identity else None,
        destinations=destinations or [],
        location=location,
        metadata=semantics or {},
    )
    agent = Agent(
        name="agent",
        tools=[tool],
        identities=[identity] if identity else [],
        location=location,
    )
    return effective_authority_relationships(Graph(agents=[agent]))[0]


def _mcp_relationship(
    root: Path,
    *,
    allowed_tools: list[str] | None = None,
    denied_tools: list[str] | None = None,
    approval: bool | None = None,
    dynamic: bool = False,
):
    location = SourceLocation(root / "agent.py", line=7)
    server = MCPServer(
        name="github",
        transport="streamable_http",
        url="https://api.github.com/mcp",
        allowed_tools=allowed_tools or [],
        denied_tools=denied_tools or [],
        approval=approval,
        location=location,
        metadata={"dynamic_tool_filter": True} if dynamic else {},
    )
    return effective_authority_relationships(
        Graph(agents=[Agent(name="agent", mcp_servers=[server], location=location)])
    )[0]


def test_relationship_classifies_evidence_backed_boundaries(tmp_path: Path) -> None:
    identity = Identity(
        name="admin",
        provider="gcp",
        roles={"roles/owner"},
        credential_source="workload_identity",
        location=SourceLocation(tmp_path / "agent.py"),
    )
    relationship = _tool_relationship(
        tmp_path,
        capabilities={"identity.admin", "network.external"},
        approval=True,
        identity=identity,
        semantics={
            "mutation_semantics": "persistent_internal_write",
            "network_semantics": "arbitrary_egress",
        },
    )

    relationship = replace(
        relationship,
        semantics={
            "mutation": "persistent_internal_write",
            "network": "arbitrary_egress",
            "sensitive_write_domain": None,
        },
    )

    classified = classify_relationship(relationship)

    assert classified.mutation.classification == "security_identity_sensitive_mutation"
    assert classified.network.classification == "arbitrary_egress"
    assert classified.identity.classification == "broad_privileged_authority"
    assert classified.control.classification == "mandatory_approval"
    assert classified.mcp_scope.classification == "not_applicable"


def test_process_execution_mutation_remains_unknown(tmp_path: Path) -> None:
    relationship = _tool_relationship(
        tmp_path,
        capabilities={"process.execute"},
        approval=True,
    )

    classified = classify_relationship(relationship)

    assert classified.mutation.classification == "unknown"
    assert classified.mutation.resolution == "unknown"


def test_mcp_mutation_is_not_assumed_read_only(tmp_path: Path) -> None:
    relationship = _mcp_relationship(
        tmp_path,
        allowed_tools=["issues_read"],
        approval=True,
    )

    classified = classify_relationship(relationship)

    assert classified.mutation.classification == "unknown"
    assert classified.mcp_scope.classification == "explicit_allowlist"


def test_specific_mcp_endpoint_is_fixed_destination(tmp_path: Path) -> None:
    relationship = _mcp_relationship(tmp_path, allowed_tools=["issues_read"])

    classified = classify_relationship(relationship)

    assert classified.network.classification == "fixed_destination"


def test_identity_categories_preserve_authority_shape(tmp_path: Path) -> None:
    workload = Identity(
        name="svc",
        credential_source="workload_identity",
        location=SourceLocation(tmp_path / "a.py"),
    )
    oauth = Identity(
        name="oauth",
        oauth_scopes={"issues:read"},
        credential_source="oauth_token",
        location=SourceLocation(tmp_path / "b.py"),
    )
    iam = Identity(
        name="iam",
        roles={"roles/viewer"},
        credential_source="workload_identity",
        location=SourceLocation(tmp_path / "c.py"),
    )
    broad = Identity(
        name="owner",
        roles={"roles/owner"},
        credential_source="workload_identity",
        location=SourceLocation(tmp_path / "d.py"),
    )

    classes = [
        classify_relationship(
            _tool_relationship(
                tmp_path,
                capabilities={"data.read"},
                approval=True,
                identity=identity,
            )
        ).identity.classification
        for identity in (workload, oauth, iam, broad)
    ]

    assert classes == [
        "workload_service_identity",
        "oauth_delegated_authority",
        "iam_authority",
        "broad_privileged_authority",
    ]


def test_control_classes_distinguish_approval_guardrail_absence_and_unknown(
    tmp_path: Path,
) -> None:
    mandatory = classify_relationship(
        _tool_relationship(tmp_path, capabilities={"data.write"}, approval=True)
    )
    guarded = classify_relationship(
        _tool_relationship(
            tmp_path,
            capabilities={"data.write"},
            approval=None,
            guardrails=True,
        )
    )
    absent = classify_relationship(
        _tool_relationship(tmp_path, capabilities={"data.write"}, approval=False)
    )
    unknown = classify_relationship(
        _tool_relationship(tmp_path, capabilities={"data.write"}, approval=None)
    )

    assert mandatory.control.classification == "mandatory_approval"
    assert guarded.control.classification == "guardrail_control"
    assert absent.control.classification == "explicitly_no_approval"
    assert unknown.control.classification == "unknown"


def test_mcp_scope_categories_preserve_unknown_dynamic_and_denylist_states(
    tmp_path: Path,
) -> None:
    explicit = classify_relationship(
        _mcp_relationship(tmp_path, allowed_tools=["issues_read"])
    )
    deny_only = classify_relationship(
        _mcp_relationship(tmp_path, denied_tools=["repo_delete"])
    )
    dynamic = classify_relationship(
        _mcp_relationship(tmp_path, dynamic=True)
    )
    unknown = classify_relationship(_mcp_relationship(tmp_path))

    assert explicit.mcp_scope.classification == "explicit_allowlist"
    assert deny_only.mcp_scope.classification == "denylist_only"
    assert dynamic.mcp_scope.classification == "dynamic_scope"
    assert unknown.mcp_scope.classification == "unknown"


def test_supported_tool_boundary_crossings_are_named_without_risk_score(
    tmp_path: Path,
) -> None:
    before_identity = Identity(
        name="svc",
        credential_source="workload_identity",
        location=SourceLocation(tmp_path / "before.py"),
    )
    after_identity = Identity(
        name="svc",
        roles={"roles/owner"},
        credential_source="workload_identity",
        location=SourceLocation(tmp_path / "after.py"),
    )
    before = _tool_relationship(
        tmp_path / "before",
        capabilities={"data.write", "network.external"},
        approval=True,
        identity=before_identity,
        destinations=[
            NetworkDestination(
                target="https://api.example.test",
                restricted=True,
                location=SourceLocation(tmp_path / "before.py"),
            )
        ],
    )
    after = _tool_relationship(
        tmp_path / "after",
        capabilities={"external.write", "network.external"},
        approval=False,
        identity=after_identity,
    )

    # Force normalized semantics that the scanner would attach before effective authority.
    before = replace(
        before,
        semantics={
            "mutation": "local_session_state_write",
            "network": None,
            "sensitive_write_domain": None,
        },
    )
    after = replace(
        after,
        semantics={
            "mutation": "external_side_effect",
            "network": "arbitrary_egress",
            "sensitive_write_domain": None,
        },
    )

    crossings = classify_boundary_crossings(before, after)
    by_family = {item.family: item for item in crossings}

    assert by_family["mutation"].direction == "expanded"
    assert by_family["mutation"].before == "local_session_mutation"
    assert by_family["mutation"].after == "external_side_effect"
    assert by_family["network"].direction == "expanded"
    assert by_family["identity"].direction == "expanded"
    assert by_family["control"].direction == "weakened"
    assert all("score" not in item.as_dict() for item in crossings)


def test_unknown_transition_does_not_become_supported_crossing(tmp_path: Path) -> None:
    before = _tool_relationship(
        tmp_path / "before",
        capabilities={"process.execute"},
        approval=True,
    )
    after = _tool_relationship(
        tmp_path / "after",
        capabilities={"external.write"},
        approval=None,
    )

    crossings = classify_boundary_crossings(before, after)

    assert not any(item.family == "mutation" for item in crossings)
    assert not any(item.family == "control" for item in crossings)


def test_mcp_allowlist_to_denylist_is_scope_expansion(tmp_path: Path) -> None:
    before = _mcp_relationship(
        tmp_path / "before",
        allowed_tools=["issues_read"],
    )
    after = _mcp_relationship(
        tmp_path / "after",
        denied_tools=["repo_delete"],
    )

    crossings = classify_boundary_crossings(before, after)

    assert len(crossings) == 1
    assert crossings[0].family == "mcp_scope"
    assert crossings[0].direction == "expanded"


def test_trust_boundary_report_is_deterministic_and_reports_unknowns(
    tmp_path: Path,
) -> None:
    tool = _tool_relationship(
        tmp_path,
        capabilities={"process.execute"},
        approval=None,
    )
    mcp = _mcp_relationship(tmp_path)

    report = trust_boundary_report([mcp, tool])

    assert report["schema_version"] == 1
    assert report["runtime_effectiveness"] == "not_verified"
    assert report["summary"]["relationships"] == 2
    assert report["summary"]["unknown_mutation"] == 2
    assert report["summary"]["unknown_control"] == 2
    assert report["summary"]["unknown_mcp_scope"] == 1
    assert [
        (item["agent"], item["target"]["kind"], item["target"]["name"])
        for item in report["relationships"]
    ] == sorted(
        (item["agent"], item["target"]["kind"], item["target"]["name"])
        for item in report["relationships"]
    )
