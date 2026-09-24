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

    assert delta["schema_version"] == 2
    assert delta["summary"] == {
        "added_relationships": 0,
        "removed_relationships": 0,
        "changed_relationships": 1,
        "expanded_relationships": 1,
        "trust_boundary_crossings": 3,
        "expanded_or_weakened_boundary_crossings": 3,
        "expanded_boundary_crossings_by_family": {
            "identity": 1,
            "mutation": 1,
        },
        "weakened_boundary_crossings_by_family": {"control": 1},
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
    crossings = {
        item["family"]: item
        for item in change["trust_boundary_crossings"]
    }
    assert crossings["mutation"]["before"] == "no_mutation"
    assert crossings["mutation"]["after"] == "internal_mutation_unspecified"
    assert crossings["mutation"]["direction"] == "expanded"
    assert crossings["identity"]["before"] == "iam_authority"
    assert crossings["identity"]["after"] == "broad_privileged_authority"
    assert crossings["identity"]["direction"] == "expanded"
    assert crossings["control"]["before"] == "mandatory_approval"
    assert crossings["control"]["after"] == "explicitly_no_approval"
    assert crossings["control"]["direction"] == "weakened"


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
    assert report["summary"]["trust_boundary_crossings"] == 2
    assert report["summary"]["expanded_or_weakened_boundary_crossings"] == 2
    assert report["effective_authority_delta"]["expansions"]
    rendered = render_markdown(report)
    assert "Expanded effective-authority relationships | 1" in rendered
    assert "Trust-boundary crossings | 2" in rendered
    assert "Expanded/weakened trust boundaries | 2" in rendered
    assert "### Application/runtime trust-boundary crossings" in rendered
    assert "**Expanded mutation boundary**" in rendered
    assert "**Weakened control boundary**" in rendered
    assert "**Authority expanded**" in rendered
    assert "capabilities_added" in rendered
    assert "approval_weakened" in rendered



def test_added_relationship_includes_head_trust_boundary_classification(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-added"
    head_root = tmp_path / "head-added"
    base_root.mkdir()
    head_root.mkdir()

    head = _graph(
        head_root,
        capabilities={"external.write", "network.external"},
        approval=False,
        roles={"roles/owner"},
        destinations=["https://external.example"],
    )

    delta = compare_effective_authority(
        Graph(),
        base_root,
        head,
        head_root,
    )

    assert delta["summary"]["added_relationships"] == 1
    added = delta["added"][0]
    assert added["expansion_reasons"] == ["new_relationship"]
    dimensions = added["trust_boundaries"]["dimensions"]
    assert dimensions["mutation"]["class"] == "external_side_effect"
    assert dimensions["identity"]["class"] == "broad_privileged_authority"
    assert dimensions["control"]["class"] == "explicitly_no_approval"
    assert added["trust_boundaries"]["runtime_effectiveness"] == "not_verified"


def test_removed_relationship_includes_base_trust_boundary_classification(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-removed"
    head_root = tmp_path / "head-removed"
    base_root.mkdir()
    head_root.mkdir()

    base = _graph(
        base_root,
        capabilities={"data.read"},
        approval=True,
        roles={"roles/viewer"},
        destinations=["https://support.example"],
    )

    delta = compare_effective_authority(
        base,
        base_root,
        Graph(),
        head_root,
    )

    assert delta["summary"]["removed_relationships"] == 1
    removed = delta["removed"][0]
    dimensions = removed["trust_boundaries"]["dimensions"]
    assert dimensions["mutation"]["class"] == "no_mutation"
    assert dimensions["identity"]["class"] == "iam_authority"
    assert dimensions["control"]["class"] == "mandatory_approval"


def test_unresolved_boundary_change_does_not_create_crossing(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-unknown"
    head_root = tmp_path / "head-unknown"
    base_root.mkdir()
    head_root.mkdir()
    location_base = SourceLocation(base_root / "agent.py")
    location_head = SourceLocation(head_root / "agent.py")

    base = Graph(
        agents=[
            Agent(
                name="support",
                tools=[
                    Tool(
                        name="send_message",
                        kind="function",
                        capabilities={"process.execute"},
                        approval=None,
                        location=location_base,
                    )
                ],
                location=location_base,
            )
        ]
    )
    head = Graph(
        agents=[
            Agent(
                name="support",
                tools=[
                    Tool(
                        name="send_message",
                        kind="function",
                        capabilities={"external.write"},
                        approval=False,
                        location=location_head,
                    )
                ],
                location=location_head,
            )
        ]
    )

    delta = compare_effective_authority(base, base_root, head, head_root)

    change = delta["changed"][0]
    assert not any(
        item["family"] == "mutation"
        for item in change["trust_boundary_crossings"]
    )
    assert not any(
        item["family"] == "control"
        for item in change["trust_boundary_crossings"]
    )
