from horustrace.security_review import build_security_review


def test_security_review_correlates_authority_and_policy_by_relationship() -> None:
    authority_delta = {
        "expansions": [
            {
                "relationship_id": "rel-1",
                "agent": "support",
                "target": {"kind": "tool", "name": "send"},
                "source_context": "runtime",
                "expansion_reasons": ["capabilities_added"],
                "trust_boundary_crossings": [
                    {
                        "family": "mutation",
                        "before": "no_mutation",
                        "after": "external_side_effect",
                        "direction": "expanded",
                    }
                ],
            }
        ]
    }
    policy_delta = {
        "introduced_violations": [
            {
                "authority_relationship_id": "rel-1",
                "clause": "allow.capabilities",
                "reason": "capabilities_outside_allowlist",
            }
        ],
        "contract_weakenings": [],
    }

    report = build_security_review(authority_delta, policy_delta)

    assert report["summary"] == {
        "items": 1,
        "authority_changes": 1,
        "policy_weakenings": 0,
        "items_with_policy_violations": 1,
        "items_with_boundary_crossings": 1,
    }
    item = report["items"][0]
    assert item["relationship_id"] == "rel-1"
    assert item["policy_violations"][0]["clause"] == "allow.capabilities"
    assert item["trust_boundary_crossings"][0]["family"] == "mutation"
    assert item["runtime_effectiveness"] == "not_verified"


def test_security_review_surfaces_policy_weakening_without_relationship() -> None:
    report = build_security_review(
        {"expansions": []},
        {
            "introduced_violations": [],
            "contract_weakenings": [
                {
                    "agent": "support",
                    "clause": "require_approval_for",
                    "change": "approval_requirement_removed",
                }
            ],
        },
    )

    assert report["summary"]["items"] == 1
    item = report["items"][0]
    assert item["kind"] == "policy_weakening"
    assert item["policy_weakening"]["clause"] == "require_approval_for"
