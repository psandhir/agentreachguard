from __future__ import annotations

import json
import subprocess
import sys


def test_ground_truth_review_status() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/ground_truth_review_status.py"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["study"] == "real-world-agent-security-2026"
    assert report["cohort_frozen"] is True
    assert report["ground_truth_locked"] is False
    assert report["drafts"]["total"] == 180
    assert report["final_truth_files"] == 0
    assert report["remaining_final_truth_files"] == 180
    assert report["second_review_required"] == 62
    assert report["tier_b"] == 60
    assert report["tier_c"] == 4
    assert report["horustrace_execution_allowed"] is False
