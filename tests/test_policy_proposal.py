import json

import yaml

from horustrace.models import (
    Agent,
    Graph,
    Identity,
    MCPServer,
    NetworkDestination,
    ResourceScope,
    Tool,
)
from horustrace.policy_proposal import (
    build_authority_policy_proposal,
    render_authority_policy_json,
    render_authority_policy_yaml,
)


def _graph() -> Graph:
    tool = Tool(
        name="ticket_writer",
        kind="function",
        capabilities={"data.read", "external.write"},
        approval=True,
        identity="support-sa",
        resources=[ResourceScope(kind="ticket", selector="tickets/*")],
        destinations=[NetworkDestination(target="https://support.example.test")],
    )
    server = MCPServer(
        name="github",
        transport="http",
        url="https://mcp.example.test",
        allowed_tools=["issues_read", "issues_update"],
    )
    return Graph(
        agents=[Agent(name="support", tools=[tool], mcp_servers=[server])],
        identities=[
            Identity(
                name="support-sa",
                provider="gcp",
                roles={"roles/viewer"},
                permissions={"tickets.read"},
                oauth_scopes={"issues:read"},
            )
        ],
    )


def test_policy_proposal_snapshots_observed_authority_without_wildcards() -> None:
    report = build_authority_policy_proposal(_graph())

    authority = report["manifest"]["agents"][0]["policy"]["authority"]
    assert authority["allow"] == {
        "capabilities": [
            "data.read",
            "external.write",
            "mcp.remote",
            "network.external",
        ],
        "identities": ["support-sa"],
        "resources": ["tickets/*"],
        "destinations": [
            "https://mcp.example.test",
            "https://support.example.test",
        ],
        "iam_roles": ["roles/viewer"],
        "permissions": ["tickets.read"],
        "oauth_scopes": ["issues:read"],
        "mcp_servers": ["github"],
    }
    assert authority["require_approval_for"] == ["data.read", "external.write"]
    assert authority["mcp_tools"] == [
        {
            "server": "github",
            "allow": ["issues_read", "issues_update"],
        }
    ]
    assert "*" not in render_authority_policy_yaml(report)


def test_policy_proposal_preserves_unresolved_authority_as_diagnostics() -> None:
    report = build_authority_policy_proposal(_graph())

    assert report["runtime_effectiveness"] == "not_verified"
    assert report["summary"]["agents_with_unresolved_authority"] == 1
    diagnostic = report["diagnostics"][0]
    assert diagnostic["agent"] == "support"
    assert "identity" in diagnostic["unresolved_dimensions"]
    assert "approval" in diagnostic["unresolved_dimensions"]


def test_policy_proposal_renderers_are_deterministic_and_parseable() -> None:
    report = build_authority_policy_proposal(_graph())

    yaml_output = render_authority_policy_yaml(report)
    assert yaml.safe_load(yaml_output) == report["manifest"]

    json_output = render_authority_policy_json(report)
    assert json.loads(json_output) == report
