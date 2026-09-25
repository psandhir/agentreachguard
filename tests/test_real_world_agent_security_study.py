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
    assert report["candidates"]["total"] == 0
    assert report["cohort"]["frozen"] is False
    assert report["cohort"]["cases"] == 0
