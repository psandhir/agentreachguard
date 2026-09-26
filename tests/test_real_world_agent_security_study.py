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
    assert report["candidates"]["total"] == 365
    assert report["candidates"]["pending"] == 281
    assert report["candidates"]["included"] == 45
    assert report["candidates"]["excluded"] == 39
    assert report["candidates"]["reviewed"] == 84
    assert report["candidates"]["prior_study_checks_pending"] == 281
    assert report["candidates"]["framework_counts"] == {
        "fastagent": 27,
        "google-adk": 75,
        "langgraph": 67,
        "mcp-custom": 66,
        "openai-agents": 65,
        "pydantic-ai": 65,
    }
    assert report["candidates"]["frozen"] is False
    assert report["cohort"]["frozen"] is False
    assert report["cohort"]["cases"] == 0
