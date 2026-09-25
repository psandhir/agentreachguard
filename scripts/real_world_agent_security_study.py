"""Validate the preregistered HorusTrace Real-World Agent Security Study 2026.

This script is intentionally validation-only until candidate selection, cohort freeze,
and independent ground truth are complete. It must not run HorusTrace against candidate
repositories during the selection phases.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
STUDY = "real-world-agent-security-2026"
DEFAULT_ROOT = Path("research/real-world-agent-security-2026")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class StudyProtocolError(ValueError):
    """Raised when a preregistered study artifact violates the protocol."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StudyProtocolError(f"{path}: cannot load JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise StudyProtocolError(f"{path}: top-level document must be an object")
    return document


def _require_study_header(document: dict[str, Any], path: Path) -> None:
    if document.get("schema_version") != SCHEMA_VERSION:
        raise StudyProtocolError(
            f"{path}: schema_version must be {SCHEMA_VERSION}"
        )
    if document.get("study") != STUDY:
        raise StudyProtocolError(f"{path}: study must be {STUDY!r}")


def _require_exact_sha(value: Any, where: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise StudyProtocolError(f"{where}: expected exact lowercase 40-character SHA")
    return value


def _require_nonempty_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StudyProtocolError(f"{where}: expected non-empty string")
    return value.strip()


def _require_bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise StudyProtocolError(f"{where}: expected boolean")
    return value


def _require_list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise StudyProtocolError(f"{where}: expected list")
    return value


def validate_protocol(path: Path) -> dict[str, Any]:
    document = _load_json(path)
    _require_study_header(document, path)

    freeze = document.get("scanner_freeze")
    if not isinstance(freeze, dict):
        raise StudyProtocolError(f"{path}: scanner_freeze must be an object")
    scanner_sha = _require_exact_sha(
        freeze.get("sha"),
        f"{path}: scanner_freeze.sha",
    )
    if freeze.get("feature_freeze") is not True:
        raise StudyProtocolError(f"{path}: scanner feature_freeze must be true")

    selection = document.get("selection")
    if not isinstance(selection, dict):
        raise StudyProtocolError(f"{path}: selection must be an object")
    target = selection.get("target_unique_repositories")
    minimum_pool = selection.get("minimum_candidate_pool")
    if target != 180:
        raise StudyProtocolError(
            f"{path}: target_unique_repositories must remain preregistered at 180"
        )
    if not isinstance(minimum_pool, int) or minimum_pool < 300:
        raise StudyProtocolError(f"{path}: minimum_candidate_pool must be >= 300")
    if selection.get("horustrace_results_may_influence_selection") is not False:
        raise StudyProtocolError(
            f"{path}: HorusTrace results must not influence selection"
        )

    strata = _require_list(selection.get("framework_strata"), f"{path}: framework_strata")
    ids: list[str] = []
    target_sum = 0
    for index, item in enumerate(strata):
        if not isinstance(item, dict):
            raise StudyProtocolError(f"{path}: framework_strata[{index}] must be object")
        stratum_id = _require_nonempty_string(
            item.get("id"),
            f"{path}: framework_strata[{index}].id",
        )
        ids.append(stratum_id)
        minimum = item.get("min")
        stratum_target = item.get("target")
        maximum = item.get("max")
        if not all(isinstance(value, int) for value in (minimum, stratum_target, maximum)):
            raise StudyProtocolError(
                f"{path}: framework_strata[{index}] bounds must be integers"
            )
        if not minimum <= stratum_target <= maximum:
            raise StudyProtocolError(
                f"{path}: framework_strata[{index}] must satisfy min <= target <= max"
            )
        target_sum += stratum_target
    if len(ids) != len(set(ids)):
        raise StudyProtocolError(f"{path}: duplicate framework stratum IDs")
    if target_sum != target:
        raise StudyProtocolError(
            f"{path}: framework target sum {target_sum} does not equal {target}"
        )

    tiers = document.get("tiers")
    if not isinstance(tiers, dict):
        raise StudyProtocolError(f"{path}: tiers must be an object")
    expected_tiers = {"tier_a": 180, "tier_b": 60, "tier_c": 25}
    for name, expected in expected_tiers.items():
        item = tiers.get(name)
        if not isinstance(item, dict) or item.get("target") != expected:
            raise StudyProtocolError(
                f"{path}: {name}.target must remain preregistered at {expected}"
            )
    if tiers["tier_b"].get("dual_review") is not True:
        raise StudyProtocolError(f"{path}: tier_b must require dual review")
    if tiers["tier_c"].get("dual_review") is not True:
        raise StudyProtocolError(f"{path}: tier_c must require dual review")

    execution = document.get("execution_rules")
    if not isinstance(execution, dict):
        raise StudyProtocolError(f"{path}: execution_rules must be object")
    prohibited_true = (
        "target_execution",
        "target_import",
        "target_install",
        "target_credentials",
        "live_cloud_calls",
    )
    for key in prohibited_true:
        if execution.get(key) is not False:
            raise StudyProtocolError(f"{path}: execution_rules.{key} must be false")
    if execution.get("exact_sha_required") is not True:
        raise StudyProtocolError(f"{path}: exact_sha_required must be true")
    if execution.get("preserve_original_baseline") is not True:
        raise StudyProtocolError(f"{path}: preserve_original_baseline must be true")

    return {
        "scanner_sha": scanner_sha,
        "target": target,
        "minimum_pool": minimum_pool,
        "strata": {item["id"]: item for item in strata},
        "tier_b_target": tiers["tier_b"]["target"],
        "tier_c_target": tiers["tier_c"]["target"],
        "tier_b_max_framework_fraction": tiers["tier_b"][
            "max_single_framework_fraction"
        ],
    }


def validate_candidates(
    path: Path,
    protocol: dict[str, Any],
) -> dict[str, Any]:
    document = _load_json(path)
    _require_study_header(document, path)
    if document.get("horustrace_results_used_for_selection") is not False:
        raise StudyProtocolError(
            f"{path}: horustrace_results_used_for_selection must be false"
        )
    if document.get("minimum_pool_size") != protocol["minimum_pool"]:
        raise StudyProtocolError(
            f"{path}: minimum_pool_size must match protocol minimum"
        )

    candidates = _require_list(document.get("candidates"), f"{path}: candidates")
    repos: list[str] = []
    pending = 0
    included = 0
    excluded = 0
    exposure_pending = 0
    frameworks: Counter[str] = Counter()
    for index, candidate in enumerate(candidates):
        where = f"{path}: candidates[{index}]"
        if not isinstance(candidate, dict):
            raise StudyProtocolError(f"{where}: expected object")
        repo = _require_nonempty_string(candidate.get("repo"), f"{where}.repo")
        repos.append(repo.lower())
        _require_exact_sha(candidate.get("sha"), f"{where}.sha")

        framework = _require_nonempty_string(
            candidate.get("framework_stratum"),
            f"{where}.framework_stratum",
        )
        if framework not in protocol["strata"]:
            raise StudyProtocolError(
                f"{where}.framework_stratum: unknown stratum {framework!r}"
            )
        frameworks[framework] += 1

        discovery = candidate.get("discovery")
        if not isinstance(discovery, dict):
            raise StudyProtocolError(f"{where}.discovery: expected object")
        _require_nonempty_string(
            discovery.get("method"),
            f"{where}.discovery.method",
        )
        _require_nonempty_string(
            discovery.get("query"),
            f"{where}.discovery.query",
        )
        _require_nonempty_string(
            discovery.get("evidence_path"),
            f"{where}.discovery.evidence_path",
        )

        decision = candidate.get("decision")
        if decision not in {"pending", "include", "exclude"}:
            raise StudyProtocolError(
                f"{where}.decision: expected pending/include/exclude"
            )
        if decision == "pending":
            pending += 1
        elif decision == "include":
            included += 1
        else:
            excluded += 1
            _require_nonempty_string(
                candidate.get("exclusion_reason"),
                f"{where}.exclusion_reason",
            )
        _require_bool(
            candidate.get("previously_studied"),
            f"{where}.previously_studied",
        )
        exposure_check = candidate.get("previously_studied_check")
        if exposure_check not in {"pending", "checked"}:
            raise StudyProtocolError(
                f"{where}.previously_studied_check: expected pending/checked"
            )
        if exposure_check == "pending":
            exposure_pending += 1

        screening = candidate.get("screening")
        if decision == "pending":
            if screening is not None:
                raise StudyProtocolError(
                    f"{where}.screening: pending candidate must not have completed screening"
                )
        else:
            if not isinstance(screening, dict):
                raise StudyProtocolError(
                    f"{where}.screening: reviewed candidate requires screening object"
                )
            if screening.get("source_only") is not True:
                raise StudyProtocolError(
                    f"{where}.screening.source_only must be true"
                )
            _require_nonempty_string(
                screening.get("reviewed_at"),
                f"{where}.screening.reviewed_at",
            )
            _require_nonempty_string(
                screening.get("rationale"),
                f"{where}.screening.rationale",
            )
            _require_nonempty_string(
                screening.get("license_status"),
                f"{where}.screening.license_status",
            )
            tier_b = screening.get("tier_b")
            tier_c = screening.get("tier_c")
            for tier_name, tier_value in (("tier_b", tier_b), ("tier_c", tier_c)):
                if not isinstance(tier_value, dict):
                    raise StudyProtocolError(
                        f"{where}.screening.{tier_name}: expected object"
                    )
                _require_bool(
                    tier_value.get("eligible"),
                    f"{where}.screening.{tier_name}.eligible",
                )
                _require_list(
                    tier_value.get("signals"),
                    f"{where}.screening.{tier_name}.signals",
                )
            if decision == "include":
                _require_nonempty_string(
                    screening.get("application_path"),
                    f"{where}.screening.application_path",
                )
            if exposure_check != "checked":
                raise StudyProtocolError(
                    f"{where}: reviewed candidate requires previously_studied_check=checked"
                )

    if len(repos) != len(set(repos)):
        raise StudyProtocolError(f"{path}: candidate repositories must be unique")

    frozen = document.get("candidate_pool_frozen")
    _require_bool(frozen, f"{path}: candidate_pool_frozen")
    if frozen:
        if len(candidates) < protocol["minimum_pool"]:
            raise StudyProtocolError(
                f"{path}: frozen pool must contain at least {protocol['minimum_pool']} candidates"
            )
        if pending:
            raise StudyProtocolError(f"{path}: frozen pool cannot contain pending decisions")
        if exposure_pending:
            raise StudyProtocolError(
                f"{path}: frozen pool cannot contain pending prior-study exposure checks"
            )

    return {
        "total": len(candidates),
        "pending": pending,
        "included": included,
        "excluded": excluded,
        "prior_study_checks_pending": exposure_pending,
        "reviewed": len(candidates) - pending,
        "framework_counts": dict(sorted(frameworks.items())),
        "frozen": frozen,
    }


def _validate_assertions(
    truth: dict[str, Any],
    *,
    path: Path,
) -> None:
    assertions = _require_list(truth.get("assertions"), f"{path}: assertions")
    assertion_ids: list[str] = []
    for index, assertion in enumerate(assertions):
        where = f"{path}: assertions[{index}]"
        if not isinstance(assertion, dict):
            raise StudyProtocolError(f"{where}: expected object")
        assertion_id = _require_nonempty_string(
            assertion.get("assertion_id"),
            f"{where}.assertion_id",
        )
        assertion_ids.append(assertion_id)
        _require_nonempty_string(assertion.get("subject"), f"{where}.subject")
        _require_nonempty_string(assertion.get("predicate"), f"{where}.predicate")
        if assertion.get("expected_state") not in {
            "present",
            "absent",
            "unresolved",
        }:
            raise StudyProtocolError(
                f"{where}.expected_state: expected present/absent/unresolved"
            )
        _require_nonempty_string(assertion.get("rationale"), f"{where}.rationale")
        evidence = _require_list(assertion.get("evidence"), f"{where}.evidence")
        if not evidence:
            raise StudyProtocolError(f"{where}.evidence: cannot be empty")
        for evidence_index, item in enumerate(evidence):
            evidence_where = f"{where}.evidence[{evidence_index}]"
            if not isinstance(item, dict):
                raise StudyProtocolError(f"{evidence_where}: expected object")
            _require_nonempty_string(item.get("path"), f"{evidence_where}.path")
            _require_nonempty_string(
                item.get("rationale"),
                f"{evidence_where}.rationale",
            )
    if len(assertion_ids) != len(set(assertion_ids)):
        raise StudyProtocolError(f"{path}: duplicate assertion IDs")


def validate_ground_truth(
    path: Path,
    *,
    case_id: str,
    tier_b: bool,
    tier_c: bool,
) -> None:
    truth = _load_json(path)
    _require_study_header(truth, path)
    if truth.get("case_id") != case_id:
        raise StudyProtocolError(f"{path}: case_id must be {case_id!r}")

    lock = truth.get("truth_lock")
    if not isinstance(lock, dict):
        raise StudyProtocolError(f"{path}: truth_lock must be object")
    if lock.get("reviewed") is not True:
        raise StudyProtocolError(f"{path}: truth_lock.reviewed must be true")
    if lock.get("horustrace_output_seen") is not False:
        raise StudyProtocolError(
            f"{path}: truth must be locked before HorusTrace output is seen"
        )
    _require_nonempty_string(lock.get("locked_at"), f"{path}: truth_lock.locked_at")
    reviewers = _require_list(lock.get("reviewers"), f"{path}: truth_lock.reviewers")
    if any(not isinstance(item, str) or not item.strip() for item in reviewers):
        raise StudyProtocolError(f"{path}: reviewers must be non-empty strings")
    if len(reviewers) != len(set(reviewers)):
        raise StudyProtocolError(f"{path}: reviewers must be unique")
    required_reviewers = 2 if (tier_b or tier_c) else 1
    if len(reviewers) < required_reviewers:
        raise StudyProtocolError(
            f"{path}: case requires at least {required_reviewers} reviewer(s)"
        )

    tier_a = truth.get("tier_a")
    if not isinstance(tier_a, dict):
        raise StudyProtocolError(f"{path}: tier_a must be object")
    for key in (
        "frameworks",
        "agent_roots",
        "tools",
        "mcp_servers",
        "delegation_edges",
        "unresolved",
    ):
        _require_list(tier_a.get(key), f"{path}: tier_a.{key}")

    if tier_b and not isinstance(truth.get("tier_b"), dict):
        raise StudyProtocolError(f"{path}: tier_b case requires tier_b truth object")
    if tier_c and not isinstance(truth.get("tier_c"), dict):
        raise StudyProtocolError(f"{path}: tier_c case requires tier_c truth object")

    _validate_assertions(truth, path=path)


def validate_cohort(
    path: Path,
    *,
    study_root: Path,
    protocol: dict[str, Any],
) -> dict[str, Any]:
    document = _load_json(path)
    _require_study_header(document, path)
    if document.get("scanner_freeze_sha") != protocol["scanner_sha"]:
        raise StudyProtocolError(
            f"{path}: scanner_freeze_sha must match protocol scanner SHA"
        )
    if document.get("horustrace_results_used_for_selection") is not False:
        raise StudyProtocolError(
            f"{path}: HorusTrace results must not influence cohort selection"
        )

    frozen = document.get("cohort_frozen")
    truth_locked = document.get("ground_truth_locked")
    _require_bool(frozen, f"{path}: cohort_frozen")
    _require_bool(truth_locked, f"{path}: ground_truth_locked")
    cases = _require_list(document.get("cases"), f"{path}: cases")
    tier_b_ids = _require_list(
        document.get("tier_b_case_ids"),
        f"{path}: tier_b_case_ids",
    )
    tier_c_ids = _require_list(
        document.get("tier_c_case_ids"),
        f"{path}: tier_c_case_ids",
    )

    if not frozen:
        if cases or tier_b_ids or tier_c_ids:
            raise StudyProtocolError(
                f"{path}: unfrozen cohort must remain empty until cohort freeze"
            )
        if truth_locked:
            raise StudyProtocolError(
                f"{path}: ground truth cannot be locked before cohort freeze"
            )
        return {
            "frozen": False,
            "truth_locked": False,
            "cases": 0,
            "tier_b": 0,
            "tier_c": 0,
        }

    if len(cases) != protocol["target"]:
        raise StudyProtocolError(
            f"{path}: frozen cohort must contain exactly {protocol['target']} cases"
        )

    case_ids: list[str] = []
    repos: list[str] = []
    frameworks: Counter[str] = Counter()
    case_by_id: dict[str, dict[str, Any]] = {}
    for index, case in enumerate(cases):
        where = f"{path}: cases[{index}]"
        if not isinstance(case, dict):
            raise StudyProtocolError(f"{where}: expected object")
        case_id = _require_nonempty_string(case.get("case_id"), f"{where}.case_id")
        repo = _require_nonempty_string(case.get("repo"), f"{where}.repo")
        _require_exact_sha(case.get("sha"), f"{where}.sha")
        _require_nonempty_string(
            case.get("application_path"),
            f"{where}.application_path",
        )
        framework = _require_nonempty_string(
            case.get("framework_stratum"),
            f"{where}.framework_stratum",
        )
        if framework not in protocol["strata"]:
            raise StudyProtocolError(
                f"{where}.framework_stratum: unknown stratum {framework!r}"
            )
        _require_bool(case.get("previously_studied"), f"{where}.previously_studied")
        _require_nonempty_string(
            case.get("ground_truth"),
            f"{where}.ground_truth",
        )
        case_ids.append(case_id)
        repos.append(repo.lower())
        frameworks[framework] += 1
        case_by_id[case_id] = case

    if len(case_ids) != len(set(case_ids)):
        raise StudyProtocolError(f"{path}: duplicate case IDs")
    if len(repos) != len(set(repos)):
        raise StudyProtocolError(f"{path}: cohort must contain unique repositories")

    exceptions = document.get("stratum_exceptions", [])
    if not isinstance(exceptions, list):
        raise StudyProtocolError(f"{path}: stratum_exceptions must be list")
    exception_strata = {
        item.get("stratum")
        for item in exceptions
        if isinstance(item, dict)
    }
    for stratum_id, bounds in protocol["strata"].items():
        count = frameworks[stratum_id]
        if count > bounds["max"]:
            raise StudyProtocolError(
                f"{path}: {stratum_id} count {count} exceeds maximum {bounds['max']}"
            )
        if count < bounds["min"] and stratum_id not in exception_strata:
            raise StudyProtocolError(
                f"{path}: {stratum_id} count {count} below minimum {bounds['min']} "
                "without documented stratum exception"
            )

    tier_b_set = set(str(item) for item in tier_b_ids)
    tier_c_set = set(str(item) for item in tier_c_ids)
    known_ids = set(case_ids)
    if len(tier_b_ids) != protocol["tier_b_target"] or len(tier_b_set) != len(tier_b_ids):
        raise StudyProtocolError(
            f"{path}: tier_b_case_ids must contain exactly {protocol['tier_b_target']} unique IDs"
        )
    if len(tier_c_ids) != protocol["tier_c_target"] or len(tier_c_set) != len(tier_c_ids):
        raise StudyProtocolError(
            f"{path}: tier_c_case_ids must contain exactly {protocol['tier_c_target']} unique IDs"
        )
    if not tier_b_set <= known_ids or not tier_c_set <= known_ids:
        raise StudyProtocolError(f"{path}: tier subsets must reference cohort cases")

    tier_b_frameworks = Counter(
        case_by_id[case_id]["framework_stratum"]
        for case_id in tier_b_set
    )
    max_allowed = int(
        protocol["tier_b_target"] * protocol["tier_b_max_framework_fraction"]
    )
    if tier_b_frameworks and max(tier_b_frameworks.values()) > max_allowed:
        raise StudyProtocolError(
            f"{path}: a Tier B framework exceeds the preregistered 40% cap"
        )
    if len(tier_b_frameworks) < 4:
        raise StudyProtocolError(
            f"{path}: Tier B must contain at least four framework strata"
        )

    if truth_locked:
        for case_id, case in case_by_id.items():
            truth_path = study_root / str(case["ground_truth"])
            if not truth_path.exists():
                raise StudyProtocolError(
                    f"{path}: missing ground truth for {case_id}: {truth_path}"
                )
            validate_ground_truth(
                truth_path,
                case_id=case_id,
                tier_b=case_id in tier_b_set,
                tier_c=case_id in tier_c_set,
            )

    return {
        "frozen": True,
        "truth_locked": truth_locked,
        "cases": len(cases),
        "tier_b": len(tier_b_set),
        "tier_c": len(tier_c_set),
        "framework_counts": dict(sorted(frameworks.items())),
    }


def validate_state(root: Path) -> dict[str, Any]:
    protocol = validate_protocol(root / "protocol.json")
    candidates = validate_candidates(root / "candidates.json", protocol)
    cohort = validate_cohort(
        root / "cohort.json",
        study_root=root,
        protocol=protocol,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "study": STUDY,
        "valid": True,
        "scanner_sha": protocol["scanner_sha"],
        "candidates": candidates,
        "cohort": cohort,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate protocol/candidate/cohort state without running HorusTrace.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.validate_only:
        print(
            "study error: execution is disabled until candidate selection, cohort freeze, "
            "and independent ground truth are complete",
            file=sys.stderr,
        )
        return 2
    try:
        result = validate_state(args.root)
    except StudyProtocolError as exc:
        print(f"study error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
