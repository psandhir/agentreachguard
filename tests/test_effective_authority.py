from pathlib import Path

from horustrace.adg import build_adg
from horustrace.effective_authority import effective_authority_report
from horustrace.models import (
    Agent,
    Graph,
    Identity,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    SourceLocation,
    Tool,
)


def _graph(root: Path) -> Graph:
    location = SourceLocation(root / "agent.py", line=7)
    identity = Identity(
        name="support-agent",
        provider="gcp",
        credential_source="workload_identity",
        roles={"roles/viewer"},
        location=location,
    )
    tool = Tool(
        name="update_ticket",
        kind="function",
        capabilities={"data.read", "data.write"},
        approval=True,
        resources=[
            ResourceScope(
                kind="ticket",
                selector="support/*",
                access={"data.read", "data.write"},
                location=location,
            )
        ],
        destinations=[
            NetworkDestination(
                target="https://support.example.test",
                restricted=True,
                location=location,
                metadata={"source": "fixture"},
            )
        ],
        identity=identity.name,
        location=location,
        metadata={
            "approval_mechanism": "human_confirmation",
            "mutation_semantics": "persistent_internal_write",
            "network_semantics": "fixed_provider",
        },
    )
    server = MCPServer(
        name="github",
        transport="streamable_http",
        url="https://api.github.com/mcp",
        authenticated=True,
        approval=False,
        allowed_tools=["issues_read", "issues_update"],
        denied_tools=["repo_delete"],
        identity=identity.name,
        location=location,
        metadata={
            "auth_mechanism": "workload_identity",
            "binding_origin": "framework_agent_configuration",
        },
    )
    graph = Graph(
        agents=[
            Agent(
                name="support",
                tools=[tool],
                mcp_servers=[server],
                identities=[identity],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, root)
    return graph


def _relationship(report: dict, kind: str, name: str) -> dict:
    return next(
        item
        for item in report["relationships"]
        if item["target"] == {"kind": kind, "name": name}
    )


def test_effective_authority_reconstructs_direct_tool_relationship(tmp_path: Path) -> None:
    report = effective_authority_report(_graph(tmp_path))
    relationship = _relationship(report, "tool", "update_ticket")

    assert relationship["agent"] == "support"
    assert relationship["capabilities"] == ["data.read", "data.write"]
    assert relationship["identity"]["name"] == "support-agent"
    assert relationship["identity"]["credential_source"] == "workload_identity"
    assert relationship["approval"] == {
        "required": True,
        "guardrails": False,
        "mechanism": "human_confirmation",
    }
    assert relationship["resources"][0]["selector"] == "support/*"
    assert relationship["destinations"][0]["target"] == "https://support.example.test"
    assert relationship["semantics"]["mutation"] == "persistent_internal_write"
    assert relationship["semantics"]["network"] == "fixed_provider"
    assert relationship["runtime_effectiveness"] == "not_verified"
    assert len(relationship["evidence"]) == 1
    assert relationship["evidence"][0]["kind"] == "INVOKES"


def test_effective_authority_reconstructs_mcp_relationship(tmp_path: Path) -> None:
    report = effective_authority_report(_graph(tmp_path))
    relationship = _relationship(report, "mcp_server", "github")

    assert relationship["agent"] == "support"
    assert relationship["capabilities"] == ["mcp.remote", "network.external"]
    assert relationship["tool_scope"] == {
        "scope": "explicit_allowlist",
        "allowed": ["issues_read", "issues_update"],
        "denied": ["repo_delete"],
        "catalogue_known": True,
    }
    assert relationship["identity"]["name"] == "support-agent"
    assert relationship["destinations"][0]["target"] == "https://api.github.com/mcp"
    assert relationship["semantics"]["binding_origin"] == "framework_agent_configuration"
    assert relationship["semantics"]["authentication_state"] == "authenticated"
    assert relationship["semantics"]["authentication_mechanism"] == "workload_identity"
    assert relationship["runtime_effectiveness"] == "not_verified"
    assert len(relationship["evidence"]) == 1


def test_effective_authority_keeps_missing_dimensions_explicit(tmp_path: Path) -> None:
    location = SourceLocation(tmp_path / "agent.py", line=3)
    graph = Graph(
        agents=[
            Agent(
                name="minimal",
                tools=[
                    Tool(
                        name="opaque",
                        kind="function",
                        capabilities={"data.write"},
                        location=location,
                    )
                ],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, tmp_path)

    relationship = effective_authority_report(graph)["relationships"][0]

    assert relationship["resolution"] == "partially_resolved"
    assert relationship["identity"] is None
    assert relationship["resources"] == []
    assert relationship["destinations"] == []
    assert relationship["unresolved"] == [
        "approval",
        "destinations",
        "identity",
        "resources",
    ]
    assert relationship["dimensions"]["identity"] == "unknown"
    assert relationship["dimensions"]["approval"] == "unknown"
    assert relationship["runtime_effectiveness"] == "not_verified"


def test_effective_authority_report_summary_counts_relationship_types(tmp_path: Path) -> None:
    report = effective_authority_report(_graph(tmp_path))

    assert report["schema_version"] == 1
    assert report["runtime_effectiveness"] == "not_verified"
    assert report["summary"]["relationships"] == 2
    assert report["summary"]["tool_relationships"] == 1
    assert report["summary"]["mcp_relationships"] == 1
    assert report["summary"]["relationships_with_identity"] == 2
    assert report["summary"]["relationships_with_approval_evidence"] == 2
    assert report["summary"]["relationships_with_destination_evidence"] == 2
