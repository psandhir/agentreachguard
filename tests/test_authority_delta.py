from pathlib import Path

from horustrace.adg import build_adg
from horustrace.authority_delta import compare_effective_authority
from horustrace.change_analysis import compare_scans, render_markdown
from horustrace.models import (
    Agent,
    Graph,
    Identity,
    NetworkDestination,
    SourceLocation,
    Tool,
)


def _graph(
    root: Path,
    *,
    capabilities: set[str],
    approval: bool,
    roles: set[str],
    destinations: list[str],
) -> Graph:
    location = SourceLocation(root / "agent.py", line=10)
    identity = Identity(
        name="support-identity",
        provider="gcp",
        roles=roles,
        credential_source="workload_identity",
        location=location,
    )
    tool = Tool(
        name="send_message",
        kind="function",
        capabilities=capabilities,
        approval=approval,
        identity=identity.name,
        destinations=[
            NetworkDestination(
                target=target,
                restricted=True,
                location=location,
            )
            for target in destinations
        ],
        location=location,
    )
    graph = Graph(
        agents=[
            Agent(
                name="support",
                tools=[tool],
                identities=[identity],
                location=location,
            )
        ]
    )
    graph.adg = build_adg(graph, root)
    return graph


def test_authority_delta_explains_semantic_expansion(tmp_path: Path) -> None:
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    base_root.mkdir()
    head_root.mkdir()

    base = _graph(
        base_root,
        capabilities={"data.read"},
        approval=True,
        roles={"roles/viewer"},
        destinations=["https://support.example"],
    )
    head = _graph(
        head_root,
        capabilities={"data.read", "data.write"},
        approval=False,
        roles={"roles/viewer", "roles/editor"},
        destinations=[
            "https://support.example",
            "https://external.example",
        ],
    )

    delta = compare_effective_authority(base, base_root, head, head_root)

    assert delta["summary"] == {
        "added_relationships": 0,
        "removed_relationships": 0,
        "changed_relationships": 1,
        "expanded_relationships": 1,
    }
    change = delta["changed"][0]
    assert change["capabilities"]["added"] == ["data.write"]
    assert change["identity"]["roles"]["added"] == ["roles/editor"]
    assert change["approval"]["before"]["required"] is True
    assert change["approval"]["after"]["required"] is False
    assert [item["target"] for item in change["destinations"]["added"]] == [
        "https://external.example"
    ]
    assert change["expansion_reasons"] == [
        "capabilities_added",
        "identity_roles_added",
        "approval_weakened",
        "destinations_added",
    ]


def test_change_report_surfaces_effective_authority_expansion(tmp_path: Path) -> None:
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    base_root.mkdir()
    head_root.mkdir()

    base = _graph(
        base_root,
        capabilities={"data.read"},
        approval=True,
        roles={"roles/viewer"},
        destinations=["https://support.example"],
    )
    head = _graph(
        head_root,
        capabilities={"data.read", "external.write"},
        approval=False,
        roles={"roles/viewer"},
        destinations=["https://support.example"],
    )

    report = compare_scans(
        base,
        [],
        base_root,
        head,
        [],
        head_root,
        base_ref="base",
        head_ref="head",
    )

    assert report["summary"]["expanded_authority_relationships"] == 1
    assert report["effective_authority_delta"]["expansions"]
    rendered = render_markdown(report)
    assert "Expanded effective-authority relationships | 1" in rendered
    assert "**Authority expanded**" in rendered
    assert "capabilities_added" in rendered
    assert "approval_weakened" in rendered
