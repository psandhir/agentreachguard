from pathlib import Path

from horustrace.authority_delta import compare_effective_authority
from horustrace.authority_policy_delta import compare_authority_contracts
from horustrace.change_analysis import compare_scans, render_console, render_markdown
from horustrace.models import (
    Agent,
    AgentPolicy,
    AuthorityContract,
    AuthorityScope,
    Graph,
    SourceLocation,
    Tool,
)


def _graph(
    root: Path,
    *,
    capabilities: set[str],
    approval: bool | None = True,
    contract: AuthorityContract | None,
) -> Graph:
    location = SourceLocation(root / "agent.py", line=7)
    return Graph(
        agents=[
            Agent(
                name="agent",
                tools=[
                    Tool(
                        name="action",
                        kind="function",
                        capabilities=capabilities,
                        approval=approval,
                        location=location,
                    )
                ],
                policy=AgentPolicy(authority=contract),
                location=location,
            )
        ]
    )


def _compare(
    base: Graph,
    base_root: Path,
    head: Graph,
    head_root: Path,
) -> dict:
    authority_delta = compare_effective_authority(
        base,
        base_root,
        head,
        head_root,
    )
    return compare_authority_contracts(
        base,
        base_root,
        head,
        head_root,
        authority_delta,
    )


def test_clean_base_to_violating_head_introduces_policy_violation(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    contract = AuthorityContract(
        allow=AuthorityScope(capabilities={"data.read"}),
    )
    base = _graph(
        base_root,
        capabilities={"data.read"},
        contract=contract,
    )
    head = _graph(
        head_root,
        capabilities={"external.write"},
        contract=contract,
    )

    delta = _compare(base, base_root, head, head_root)

    assert delta["summary"]["base_violations"] == 0
    assert delta["summary"]["head_violations"] == 1
    assert delta["summary"]["introduced_violations"] == 1
    violation = delta["introduced_violations"][0]
    assert violation["clause"] == "allow.capabilities"
    assert violation["reason"] == "capabilities_outside_allowlist"
    assert violation["relationship_location"]["path"] == "agent.py"
    assert violation["source_context"] == "runtime"
    assert any(
        crossing["family"] == "mutation"
        and crossing["direction"] == "expanded"
        for crossing in violation["trust_boundary_crossings"]
    )


def test_historical_unchanged_violation_is_not_reintroduced(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    contract = AuthorityContract(
        allow=AuthorityScope(capabilities={"data.read"}),
    )
    base = _graph(
        base_root,
        capabilities={"external.write"},
        contract=contract,
    )
    head = _graph(
        head_root,
        capabilities={"external.write"},
        contract=contract,
    )

    delta = _compare(base, base_root, head, head_root)

    assert delta["summary"]["base_violations"] == 1
    assert delta["summary"]["head_violations"] == 1
    assert delta["summary"]["introduced_violations"] == 0
    assert delta["summary"]["resolved_violations"] == 0


def test_additional_clause_violation_is_introduced_without_rebaselining_debt(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    base_contract = AuthorityContract(
        allow=AuthorityScope(capabilities={"data.read"}),
    )
    head_contract = AuthorityContract(
        allow=AuthorityScope(capabilities={"data.read"}),
        require_approval_for={"external.write"},
    )
    base = _graph(
        base_root,
        capabilities={"external.write"},
        approval=False,
        contract=base_contract,
    )
    head = _graph(
        head_root,
        capabilities={"external.write"},
        approval=False,
        contract=head_contract,
    )

    delta = _compare(base, base_root, head, head_root)

    assert delta["summary"]["base_violations"] == 1
    assert delta["summary"]["head_violations"] == 2
    assert delta["summary"]["introduced_violations"] == 1
    assert delta["introduced_violations"][0]["clause"] == "require_approval_for"
    assert (
        delta["introduced_violations"][0]["reason"]
        == "required_approval_explicitly_disabled"
    )


def test_resolved_violation_is_reported_separately(tmp_path: Path) -> None:
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    contract = AuthorityContract(
        allow=AuthorityScope(capabilities={"data.read"}),
    )
    base = _graph(
        base_root,
        capabilities={"external.write"},
        contract=contract,
    )
    head = _graph(
        head_root,
        capabilities={"data.read"},
        contract=contract,
    )

    delta = _compare(base, base_root, head, head_root)

    assert delta["summary"]["introduced_violations"] == 0
    assert delta["summary"]["resolved_violations"] == 1
    assert delta["resolved_violations"][0]["clause"] == "allow.capabilities"


def test_unresolved_only_change_does_not_become_violation(tmp_path: Path) -> None:
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    base = _graph(
        base_root,
        capabilities={"data.read"},
        contract=None,
    )
    head = _graph(
        head_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            allow=AuthorityScope(identities={"expected-service-account"}),
        ),
    )

    delta = _compare(base, base_root, head, head_root)

    assert delta["summary"]["introduced_violations"] == 0
    assert delta["summary"]["introduced_unresolved"] == 1
    unresolved = delta["introduced_unresolved"][0]
    assert unresolved["clause"] == "allow.identities"
    assert unresolved["reason"] == "identities_evidence_unknown"
    assert unresolved["runtime_effectiveness"] == "not_verified"


def test_result_identity_is_checkout_path_independent(tmp_path: Path) -> None:
    contract = AuthorityContract(
        deny=AuthorityScope(capabilities={"external.write"}),
    )
    first_root = tmp_path / "one"
    second_root = tmp_path / "two"
    empty_root = tmp_path / "empty"
    first = _graph(
        first_root,
        capabilities={"external.write"},
        contract=contract,
    )
    second = _graph(
        second_root,
        capabilities={"external.write"},
        contract=contract,
    )

    first_delta = _compare(Graph(), empty_root, first, first_root)
    second_delta = _compare(Graph(), empty_root, second, second_root)

    assert (
        first_delta["introduced_violations"][0]["result_id"]
        == second_delta["introduced_violations"][0]["result_id"]
    )



def test_security_delta_renders_introduced_contract_violation(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-report"
    head_root = tmp_path / "head-report"
    contract = AuthorityContract(
        allow=AuthorityScope(capabilities={"data.read"}),
    )
    base = _graph(
        base_root,
        capabilities={"data.read"},
        contract=contract,
    )
    head = _graph(
        head_root,
        capabilities={"external.write"},
        contract=contract,
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

    assert report["summary"]["base_policy_violations"] == 0
    assert report["summary"]["head_policy_violations"] == 1
    assert report["summary"]["introduced_policy_violations"] == 1
    assert report["summary"]["resolved_policy_violations"] == 0

    console = render_console(report)
    assert "Introduced Authority Contract violations" in console
    assert "clause=allow.capabilities" in console
    assert "reason=capabilities_outside_allowlist" in console

    markdown = render_markdown(report)
    assert "Introduced Authority Contract violations | 1" in markdown
    assert "### Introduced Authority Contract violations" in markdown
    assert "clause `allow.capabilities`" in markdown
    assert "reason `capabilities_outside_allowlist`" in markdown



def test_policy_delta_normalizes_nested_explanation_locations(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-explain"
    head_root = tmp_path / "head-explain"
    base_contract = AuthorityContract(
        allow=AuthorityScope(capabilities={"data.read"}),
        location=SourceLocation(
            base_root / "horustrace.manifest.yaml",
            line=5,
            column=7,
        ),
        clause_locations={
            "allow.capabilities": SourceLocation(
                base_root / "horustrace.manifest.yaml",
                line=8,
                column=25,
            )
        },
    )
    head_contract = AuthorityContract(
        allow=AuthorityScope(capabilities={"data.read"}),
        location=SourceLocation(
            head_root / "horustrace.manifest.yaml",
            line=5,
            column=7,
        ),
        clause_locations={
            "allow.capabilities": SourceLocation(
                head_root / "horustrace.manifest.yaml",
                line=8,
                column=25,
            )
        },
    )
    base = _graph(
        base_root,
        capabilities={"data.read"},
        contract=base_contract,
    )
    head = _graph(
        head_root,
        capabilities={"external.write"},
        contract=head_contract,
    )

    delta = _compare(base, base_root, head, head_root)
    violation = delta["introduced_violations"][0]

    assert violation["contract_location"]["path"] == "horustrace.manifest.yaml"
    assert violation["relationship_location"]["path"] == "agent.py"
    assert (
        violation["explanation"]["policy"]["location"]["path"]
        == "horustrace.manifest.yaml"
    )
    assert violation["explanation"]["authority"]["location"]["path"] == "agent.py"
