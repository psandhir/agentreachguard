from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STUDY = ROOT / "research" / "real-world-agent-security-2026"
COHORT = STUDY / "cohort.json"
DRAFT_INDEX = STUDY / "ground-truth-drafts" / "review-index.json"
FINAL_DIR = STUDY / "ground-truth"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_status() -> dict:
    cohort = load_json(COHORT)
    index = load_json(DRAFT_INDEX)
    cases = index["cases"]
    final_files = {p.stem for p in FINAL_DIR.glob("*.json")} if FINAL_DIR.exists() else set()

    statuses = Counter(item["status"] for item in cases)
    second_review = [item for item in cases if item["second_review_required"]]
    completed = [item for item in cases if item["case_id"] in final_files]

    return {
        "study": "real-world-agent-security-2026",
        "cohort_frozen": cohort["cohort_frozen"],
        "ground_truth_locked": cohort["ground_truth_locked"],
        "drafts": {
            "total": len(cases),
            "status_counts": dict(sorted(statuses.items())),
        },
        "final_truth_files": len(completed),
        "remaining_final_truth_files": len(cases) - len(completed),
        "second_review_required": len(second_review),
        "tier_b": sum(1 for item in cases if item["tier_b"]),
        "tier_c": sum(1 for item in cases if item["tier_c"]),
        "horustrace_execution_allowed": cohort["ground_truth_locked"] is True,
    }


def main() -> int:
    print(json.dumps(build_status(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
