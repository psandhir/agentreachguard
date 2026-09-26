from __future__ import annotations

import importlib.util
from pathlib import Path


def _module():
    path = Path("scripts/real_world_agent_security_compare.py")
    spec = importlib.util.spec_from_file_location("real_world_agent_security_compare", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _report(scanner_sha: str, *, improved: bool) -> dict:
    agent_precision = 0.96 if improved else 0.9706
    agent_recall = 0.70 if improved else 0.4993
    langgraph_agent = 0.82 if improved else 0.25
    langgraph_tools = 0.72 if improved else 0.068
    custom_agent = 0.62 if improved else 0.0625
    custom_tools = 0.61 if improved else 0.0
    mcp_recall = 0.86 if improved else 0.2727
    return {
        "study": "real-world-agent-security-2026",
        "scanner_sha": scanner_sha,
        "execution_mode": "postfix" if improved else "baseline",
        "cohort_cases": 180,
        "summary": {
            "successful_cases": 180 if improved else 179,
            "analysis_incomplete_cases": 90 if improved else 94,
        },
        "execution_failures": [] if improved else [{"case_id": "rw-177"}],
        "metrics": {
            "agent_entities": {"precision": agent_precision, "recall": agent_recall},
            "tools": {"precision": 0.50, "recall": 0.40 if improved else 0.267},
            "mcp_servers": {"precision": 0.90, "recall": mcp_recall},
            "delegation_edges": {"precision": 0.94, "recall": 0.80},
            "effective_authority": {"precision": 0.30, "recall": 0.65},
        },
        "per_framework": {
            "langgraph": {
                "agent_entities": {"precision": 0.95, "recall": langgraph_agent},
                "tools": {"precision": 0.90, "recall": langgraph_tools},
                "mcp_servers": {"precision": None, "recall": None},
                "effective_authority": {"precision": 0.20, "recall": None},
            },
            "mcp-custom": {
                "agent_entities": {"precision": 0.95, "recall": custom_agent},
                "tools": {"precision": 0.90, "recall": custom_tools},
                "mcp_servers": {"precision": 0.90, "recall": mcp_recall},
                "effective_authority": {"precision": None, "recall": None},
            },
        },
    }


def test_compare_reports_v09_gates_and_fixed_execution_failure() -> None:
    module = _module()
    baseline = _report("a" * 40, improved=False)
    candidate = _report("b" * 40, improved=True)

    result = module.compare(baseline, candidate)

    assert result["v09_gates_met"] is True
    assert result["execution"]["fixed_failures"] == ["rw-177"]
    assert result["execution"]["new_failures"] == []
    assert result["analysis_incomplete"]["delta"] == -4
    assert result["metric_deltas"]["agent_entities"]["recall"]["delta"] > 0


def test_compare_flags_precision_regression_even_when_recall_improves() -> None:
    module = _module()
    baseline = _report("a" * 40, improved=False)
    candidate = _report("b" * 40, improved=True)
    candidate["metrics"]["agent_entities"]["precision"] = 0.90

    result = module.compare(baseline, candidate)

    assert result["v09_gates_met"] is False
    assert any(
        item["scope"] == "overall"
        and item["dimension"] == "agent_entities"
        and item["measure"] == "precision"
        for item in result["regressions"]
    )


def test_compare_rejects_different_cohort_size() -> None:
    module = _module()
    baseline = _report("a" * 40, improved=False)
    candidate = _report("b" * 40, improved=True)
    candidate["cohort_cases"] = 179

    try:
        module.compare(baseline, candidate)
    except ValueError as exc:
        assert "cohort size" in str(exc)
    else:
        raise AssertionError("expected cohort-size mismatch to fail")
