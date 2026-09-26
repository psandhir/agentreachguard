from __future__ import annotations

import json
import subprocess
import sys


def test_real_world_agent_security_protocol_is_valid() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/real_world_agent_security_study.py",
            "--validate-only",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["valid"] is True
    assert report["study"] == "real-world-agent-security-2026"
    assert report["scanner_sha"] == "418db4e29798a7d25df686dd7bccfd9fefa225bd"
    assert report["candidates"]["total"] == 381
    assert report["candidates"]["pending"] == 0
    assert report["candidates"]["included"] == 196
    assert report["candidates"]["excluded"] == 185
    assert report["candidates"]["reviewed"] == 381
    assert report["candidates"]["prior_study_checks_pending"] == 0
    assert report["candidates"]["framework_counts"] == {
        "fastagent": 26,
        "google-adk": 75,
        "langgraph": 67,
        "mcp-custom": 74,
        "openai-agents": 73,
        "pydantic-ai": 66,
    }
    assert report["candidates"]["frozen"] is True
    assert report["cohort"]["frozen"] is True
    assert report["cohort"]["cases"] == 180\n    assert report["cohort"]["tier_b"] == 60\n    assert report["cohort"]["tier_c"] == 4\n    assert report["cohort"]["truth_locked"] is False\n    assert report["cohort"]["framework_counts"] == {\n        "fastagent": 3,\n        "google-adk": 37,\n        "langgraph": 35,\n        "mcp-custom": 40,\n        "openai-agents": 31,\n        "pydantic-ai": 34,\n    }
