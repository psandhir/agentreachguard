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
    MCPToolContract,
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


def test_contract_delta_detects_scope_weakening_and_tightening(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-contract"
    head_root = tmp_path / "head-contract"
    base = _graph(
        base_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            allow=AuthorityScope(capabilities={"data.read"}),
            deny=AuthorityScope(capabilities={"process.execute"}),
        ),
    )
    head = _graph(
        head_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            allow=AuthorityScope(capabilities={"data.*"}),
            deny=AuthorityScope(capabilities={"process.*"}),
        ),
    )

    delta = _compare(base, base_root, head, head_root)

    weakenings = delta["contract_weakenings"]
    strengthenings = delta["contract_strengthenings"]
    assert [(item["clause"], item["change"]) for item in weakenings] == [
        ("allow.capabilities", "allowlist_widened"),
    ]
    assert [(item["clause"], item["change"]) for item in strengthenings] == [
        ("deny.capabilities", "deny_constraint_added"),
    ]


def test_contract_delta_detects_deny_and_approval_removal(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-controls"
    head_root = tmp_path / "head-controls"
    base = _graph(
        base_root,
        capabilities={"process.execute"},
        approval=False,
        contract=AuthorityContract(
            deny=AuthorityScope(capabilities={"process.execute"}),
            require_approval_for={"process.execute"},
        ),
    )
    head = _graph(
        head_root,
        capabilities={"process.execute"},
        approval=False,
        contract=AuthorityContract(),
    )

    delta = _compare(base, base_root, head, head_root)

    # Removing the complete restrictive contract is represented once rather than
    # as a cascade of per-clause removals.
    assert delta["summary"]["contract_weakenings"] == 1
    weakening = delta["contract_weakenings"][0]
    assert weakening["clause"] == "authority"
    assert weakening["change"] == "contract_removed"
    assert weakening["before"] == ["contract_present"]
    assert weakening["after"] == []


def test_contract_delta_detects_mcp_scope_weakening(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-mcp"
    head_root = tmp_path / "head-mcp"
    base = _graph(
        base_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            mcp_tools=[
                MCPToolContract(
                    server="github",
                    allowed_tools={"issues_read"},
                    denied_tools={"repo_delete"},
                )
            ]
        ),
    )
    head = _graph(
        head_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            mcp_tools=[
                MCPToolContract(
                    server="github",
                    allowed_tools={"issues_read", "repo_write"},
                    denied_tools=set(),
                )
            ]
        ),
    )

    delta = _compare(base, base_root, head, head_root)

    assert {
        (item["clause"], item["change"])
        for item in delta["contract_weakenings"]
    } == {
        ("mcp_tools.github.allow", "mcp_allowlist_widened"),
        ("mcp_tools.github.deny", "mcp_deny_removed"),
    }


def test_contract_delta_detects_allowlist_removal_without_false_narrowing(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-allow"
    head_root = tmp_path / "head-allow"
    base = _graph(
        base_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            allow=AuthorityScope(capabilities={"data.*"}),
            deny=AuthorityScope(capabilities={"process.execute"}),
        ),
    )
    head = _graph(
        head_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            allow=AuthorityScope(),
            deny=AuthorityScope(capabilities={"process.execute"}),
        ),
    )

    delta = _compare(base, base_root, head, head_root)

    assert delta["summary"]["contract_weakenings"] == 1
    assert delta["contract_weakenings"][0]["change"] == "constraint_removed"


def test_contract_delta_pattern_narrowing_is_strengthening_not_weakening(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-pattern"
    head_root = tmp_path / "head-pattern"
    base = _graph(
        base_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            allow=AuthorityScope(capabilities={"data.*"}),
        ),
    )
    head = _graph(
        head_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            allow=AuthorityScope(capabilities={"data.read"}),
        ),
    )

    delta = _compare(base, base_root, head, head_root)

    assert delta["contract_weakenings"] == []
    assert delta["summary"]["contract_strengthenings"] == 1
    assert delta["contract_strengthenings"][0]["change"] == "allowlist_narrowed"


def test_contract_removal_fails_only_when_agent_still_exists(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-agent"
    head_root = tmp_path / "head-agent"
    base = _graph(
        base_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            deny=AuthorityScope(capabilities={"process.execute"}),
        ),
    )
    head = Graph()

    delta = _compare(base, base_root, head, head_root)

    assert delta["contract_weakenings"] == []
    assert delta["summary"]["contract_changes"] == 0


def test_contract_change_ids_are_checkout_path_independent(
    tmp_path: Path,
) -> None:
    def delta_for(root: Path) -> dict:
        base_root = root / "base"
        head_root = root / "head"
        base = _graph(
            base_root,
            capabilities={"data.read"},
            contract=AuthorityContract(
                deny=AuthorityScope(capabilities={"process.execute"}),
            ),
        )
        head = _graph(
            head_root,
            capabilities={"data.read"},
            contract=AuthorityContract(),
        )
        return _compare(base, base_root, head, head_root)

    first = delta_for(tmp_path / "one")
    second = delta_for(tmp_path / "two")

    assert (
        first["contract_weakenings"][0]["change_id"]
        == second["contract_weakenings"][0]["change_id"]
    )


def test_security_delta_renders_contract_weakening(
    tmp_path: Path,
) -> None:
    base_root = tmp_path / "base-render-weakening"
    head_root = tmp_path / "head-render-weakening"
    base = _graph(
        base_root,
        capabilities={"data.read"},
        contract=AuthorityContract(
            deny=AuthorityScope(capabilities={"process.execute"}),
        ),
    )
    head = _graph(
        head_root,
        capabilities={"data.read"},
        contract=AuthorityContract(),
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

    assert report["summary"]["authority_contract_weakenings"] == 1
    console = render_console(report)
    assert "Authority Contract weakenings" in console
    assert "change=contract_removed" in console

    markdown = render_markdown(report)
    assert "Authority Contract weakenings | 1" in markdown
    assert "### Authority Contract weakenings" in markdown
    assert "change `contract_removed`" in markdown
