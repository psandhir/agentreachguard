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
    assert report["candidates"]["pending"] == 353
    assert report["candidates"]["included"] == 10
    assert report["candidates"]["excluded"] == 2
    assert report["candidates"]["reviewed"] == 12
    assert report["candidates"]["prior_study_checks_pending"] == 353
    assert report["candidates"]["framework_counts"] == {
        "fastagent": 29,
        "google-adk": 75,
        "langgraph": 66,
        "mcp-custom": 65,
        "openai-agents": 65,
        "pydantic-ai": 65,
    }
    assert report["candidates"]["frozen"] is False
    assert report["cohort"]["frozen"] is False
    assert report["cohort"]["cases"] == 0
