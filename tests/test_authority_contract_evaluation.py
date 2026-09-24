from pathlib import Path

from horustrace.authority_contract import authority_contract_report
from horustrace.models import (
    Agent,
    AgentPolicy,
    AuthorityContract,
    AuthorityScope,
    Graph,
    Identity,
    MCPServer,
    MCPToolContract,
    NetworkDestination,
    ResourceScope,
    SourceLocation,
    Tool,
)


def _contract(**kwargs) -> AuthorityContract:
    return AuthorityContract(**kwargs)


def test_denied_capability_produces_stable_relationship_linked_violation(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=7)
    graph = Graph(
        agents=[
            Agent(
                name="support",
                tools=[
                    Tool(
                        name="shell",
                        kind="function",
                        capabilities={"process.execute"},
                        approval=True,
                        location=location,
                    )
                ],
                policy=AgentPolicy(
                    authority=_contract(
                        deny=AuthorityScope(capabilities={"process.execute"}),
                        location=SourceLocation(tmp_path / "horustrace.manifest.yaml"),
                    )
                ),
                location=location,
            )
        ]
    )

    report = authority_contract_report(graph)

    assert report["summary"] == {
        "agents_with_contract": 1,
        "relationships_evaluated": 1,
        "compliant_relationships": 0,
        "violation_relationships": 1,
        "unresolved_relationships": 0,
        "violations": 1,
        "unresolved": 0,
    }
    assert report["relationships"][0]["status"] == "violation"
    violation = report["violations"][0]
    assert violation["clause"] == "deny.capabilities"
    assert violation["reason"] == "denied_capabilities_observed"
    assert violation["observed"] == ["process.execute"]
    assert violation["authority_relationship_id"].startswith("authority-v1:")
    assert violation["result_id"].startswith("contract-violation-v1:")
    assert violation["runtime_effectiveness"] == "not_verified"


def test_allowlists_support_existing_wildcard_matching_semantics(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=9)
    graph = Graph(
        agents=[
            Agent(
                name="support",
                tools=[
                    Tool(
                        name="update_ticket",
                        kind="function",
                        capabilities={"data.write"},
                        approval=True,
                        resources=[
                            ResourceScope(
                                kind="ticket",
                                selector="tickets/eu/123",
                                access={"data.write"},
                                location=location,
                            )
                        ],
                        destinations=[
                            NetworkDestination(
                                target="https://evil.example.test",
                                location=location,
                            )
                        ],
                        location=location,
                    )
                ],
                policy=AgentPolicy(
                    authority=_contract(
                        allow=AuthorityScope(
                            capabilities={"data.*"},
                            resources={"tickets/eu/*"},
                            destinations={"https://support.example.test/*"},
                        )
                    )
                ),
            )
        ]
    )

    report = authority_contract_report(graph)

    assert report["summary"]["violations"] == 1
    assert report["violations"][0]["clause"] == "allow.destinations"
    assert report["violations"][0]["observed"] == ["https://evil.example.test"]


def test_unknown_identity_authority_is_unresolved_not_violation(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py")
    graph = Graph(
        agents=[
            Agent(
                name="support",
                tools=[
                    Tool(
                        name="read",
                        kind="function",
                        capabilities={"data.read"},
                        approval=True,
                        location=location,
                    )
                ],
                policy=AgentPolicy(
                    authority=_contract(
                        allow=AuthorityScope(identities={"support-bot"}),
                        deny=AuthorityScope(iam_roles={"roles/owner"}),
                    )
                ),
            )
        ]
    )

    report = authority_contract_report(graph)

    assert report["summary"]["violations"] == 0
    assert report["summary"]["unresolved"] == 2
    assert {item["clause"] for item in report["unresolved"]} == {
        "allow.identities",
        "deny.iam_roles",
    }
    assert all(
        item["reason"].endswith("_evidence_unknown")
        for item in report["unresolved"]
    )


def test_identity_role_permission_and_oauth_constraints_use_relationship_evidence(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "agent.py")
    identity = Identity(
        name="support-bot",
        provider="gcp",
        roles={"roles/viewer", "roles/owner"},
        permissions={"tickets.read", "iam.setPolicy"},
        oauth_scopes={"issues:read", "repo:admin"},
        credential_source="workload_identity",
        location=location,
    )
    graph = Graph(
        agents=[
            Agent(
                name="support",
                identities=[identity],
                tools=[
                    Tool(
                        name="update",
                        kind="function",
                        capabilities={"data.write"},
                        approval=True,
                        identity="support-bot",
                        location=location,
                    )
                ],
                policy=AgentPolicy(
                    authority=_contract(
                        allow=AuthorityScope(
                            identities={"support-bot"},
                            iam_roles={"roles/viewer"},
                            permissions={"tickets.*"},
                            oauth_scopes={"issues:*"},
                        ),
                        deny=AuthorityScope(
                            iam_roles={"roles/owner"},
                            permissions={"iam.*"},
                            oauth_scopes={"repo:*"},
                        ),
                    )
                ),
            )
        ]
    )

    report = authority_contract_report(graph)

    clauses = {item["clause"] for item in report["violations"]}
    assert clauses == {
        "allow.iam_roles",
        "allow.permissions",
        "allow.oauth_scopes",
        "deny.iam_roles",
        "deny.permissions",
        "deny.oauth_scopes",
    }


def test_required_approval_distinguishes_disabled_from_unproven(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py")
    contract = _contract(require_approval_for={"external.write"})
    graph = Graph(
        agents=[
            Agent(
                name="publisher",
                tools=[
                    Tool(
                        name="explicitly_unsafe",
                        kind="function",
                        capabilities={"external.write"},
                        approval=False,
                        location=location,
                    ),
                    Tool(
                        name="unknown_control",
                        kind="function",
                        capabilities={"external.write"},
                        approval=None,
                        guardrails=True,
                        location=location,
                    ),
                ],
                policy=AgentPolicy(authority=contract),
            )
        ]
    )

    report = authority_contract_report(graph)

    assert report["summary"]["violations"] == 1
    assert report["summary"]["unresolved"] == 1
    assert report["violations"][0]["reason"] == "required_approval_explicitly_disabled"
    assert report["unresolved"][0]["reason"] == "required_approval_not_proven"


def test_mcp_contract_rejects_server_and_tool_scope_expansion(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py")
    graph = Graph(
        agents=[
            Agent(
                name="support",
                mcp_servers=[
                    MCPServer(
                        name="github",
                        transport="streamable_http",
                        url="https://api.github.com/mcp",
                        allowed_tools=["issues_read", "repo_delete"],
                        location=location,
                    )
                ],
                policy=AgentPolicy(
                    authority=_contract(
                        allow=AuthorityScope(mcp_servers={"github"}),
                        mcp_tools=[
                            MCPToolContract(
                                server="github",
                                allowed_tools={"issues_read"},
                                denied_tools={"repo_delete"},
                            )
                        ],
                    )
                ),
            )
        ]
    )

    report = authority_contract_report(graph)

    reasons = {item["reason"] for item in report["violations"]}
    assert reasons == {
        "mcp_tools_outside_allowlist",
        "denied_mcp_tool_explicitly_allowed",
    }


def test_mcp_allowlist_requirement_detects_unrestricted_scope(tmp_path: Path) -> None:
    graph = Graph(
        agents=[
            Agent(
                name="support",
                mcp_servers=[
                    MCPServer(
                        name="github",
                        transport="streamable_http",
                        url="https://api.github.com/mcp",
                    )
                ],
                policy=AgentPolicy(
                    authority=_contract(
                        mcp_tools=[
                            MCPToolContract(
                                server="github",
                                allowed_tools={"issues_read"},
                            )
                        ]
                    )
                ),
            )
        ]
    )

    report = authority_contract_report(graph)

    assert report["summary"]["violations"] == 1
    assert (
        report["violations"][0]["reason"]
        == "mcp_explicit_allowlist_not_enforced"
    )


def test_denied_mcp_tool_with_unknown_catalogue_remains_unresolved(tmp_path: Path) -> None:
    graph = Graph(
        agents=[
            Agent(
                name="support",
                mcp_servers=[
                    MCPServer(
                        name="github",
                        transport="streamable_http",
                        url="https://api.github.com/mcp",
                    )
                ],
                policy=AgentPolicy(
                    authority=_contract(
                        mcp_tools=[
                            MCPToolContract(
                                server="github",
                                denied_tools={"repo_delete"},
                            )
                        ]
                    )
                ),
            )
        ]
    )

    report = authority_contract_report(graph)

    assert report["summary"]["violations"] == 0
    assert report["summary"]["unresolved"] == 1
    assert (
        report["unresolved"][0]["reason"]
        == "denied_mcp_tool_absence_not_proven"
    )


def test_violation_ids_do_not_depend_on_checkout_path(tmp_path: Path) -> None:
    def make_graph(root: Path) -> Graph:
        return Graph(
            agents=[
                Agent(
                    name="agent",
                    tools=[
                        Tool(
                            name="shell",
                            kind="function",
                            capabilities={"process.execute"},
                            approval=True,
                            location=SourceLocation(root / "agent.py"),
                        )
                    ],
                    policy=AgentPolicy(
                        authority=_contract(
                            deny=AuthorityScope(capabilities={"process.execute"}),
                            location=SourceLocation(root / "horustrace.manifest.yaml"),
                        )
                    ),
                )
            ]
        )

    first = authority_contract_report(make_graph(tmp_path / "a"))
    second = authority_contract_report(make_graph(tmp_path / "b"))

    assert first["violations"][0]["result_id"] == second["violations"][0]["result_id"]
    assert (
        first["violations"][0]["authority_relationship_id"]
        == second["violations"][0]["authority_relationship_id"]
    )


def test_relationship_outcome_is_compliant_when_supported_evidence_satisfies_contract(
    tmp_path: Path,
) -> None:
    location = SourceLocation(tmp_path / "agent.py")
    graph = Graph(
        agents=[
            Agent(
                name="reader",
                tools=[
                    Tool(
                        name="read",
                        kind="function",
                        capabilities={"data.read"},
                        approval=True,
                        resources=[
                            ResourceScope(
                                kind="ticket",
                                selector="tickets/123",
                                access={"data.read"},
                                location=location,
                            )
                        ],
                        destinations=[
                            NetworkDestination(
                                target="https://support.example.test/api",
                                location=location,
                            )
                        ],
                        location=location,
                    )
                ],
                policy=AgentPolicy(
                    authority=_contract(
                        allow=AuthorityScope(
                            capabilities={"data.read"},
                            resources={"tickets/*"},
                            destinations={"https://support.example.test/*"},
                        )
                    )
                ),
            )
        ]
    )

    report = authority_contract_report(graph)

    assert report["summary"]["compliant_relationships"] == 1
    assert report["summary"]["violations"] == 0
    assert report["summary"]["unresolved"] == 0
    assert report["relationships"][0]["status"] == "compliant"



def test_violation_fingerprint_excludes_sensitive_observed_values(tmp_path: Path) -> None:
    def make_graph(identity_name: str) -> Graph:
        location = SourceLocation(tmp_path / "agent.py")
        identity = Identity(
            name=identity_name,
            provider="generic",
            credential_source="environment",
            location=location,
        )
        return Graph(
            agents=[
                Agent(
                    name="agent",
                    identities=[identity],
                    tools=[
                        Tool(
                            name="send",
                            kind="function",
                            capabilities={"external.write"},
                            identity=identity_name,
                            approval=True,
                            location=location,
                        )
                    ],
                    policy=AgentPolicy(
                        authority=_contract(
                            allow=AuthorityScope(identities={"approved-principal"}),
                        )
                    ),
                )
            ]
        )

    first = authority_contract_report(make_graph("secret-principal-a"))
    second = authority_contract_report(make_graph("secret-principal-b"))

    assert first["violations"][0]["observed"] != second["violations"][0]["observed"]
    assert first["violations"][0]["result_id"] == second["violations"][0]["result_id"]
