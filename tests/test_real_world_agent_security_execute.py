from __future__ import annotations

import importlib.util
from pathlib import Path


def _module():
    path = Path("scripts/real_world_agent_security_execute.py")
    spec = importlib.util.spec_from_file_location("real_world_agent_security_execute", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_postfix_mode_is_explicit_and_baseline_remains_default() -> None:
    module = _module()
    parser = module.parser()

    baseline = parser.parse_args(
        [
            "--scanner-sha",
            "a" * 40,
            "--output-json",
            "result.json",
            "--output-markdown",
            "result.md",
        ]
    )
    postfix = parser.parse_args(
        [
            "--scanner-sha",
            "b" * 40,
            "--mode",
            "postfix",
            "--output-json",
            "result.json",
            "--output-markdown",
            "result.md",
        ]
    )

    assert baseline.mode == "baseline"
    assert postfix.mode == "postfix"


def test_aggregate_records_execution_mode_and_frozen_baseline_sha() -> None:
    module = _module()
    cohort = {
        "scanner_freeze_sha": "a" * 40,
        "ground_truth_reference": {},
        "tier_c_case_ids": [],
    }

    report = module.aggregate(
        [],
        "b" * 40,
        cohort,
        execution_mode="postfix",
    )

    assert report["scanner_sha"] == "b" * 40
    assert report["baseline_scanner_sha"] == "a" * 40
    assert report["execution_mode"] == "postfix"

def test_agent_entity_scoring_includes_workflow_nodes_but_not_tools() -> None:
    module = _module()
    nodes = [
        {"kind": "agent", "name": "workflow"},
        {"kind": "workflow_node", "name": "chatbot"},
        {"kind": "tool", "name": "search"},
    ]

    predicted = module.predicted_nodes_for_dimension(nodes, "agent_entities")

    assert [item["name"] for item in predicted] == ["workflow", "chatbot"]

