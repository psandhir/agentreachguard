from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "deployment_authority_study.py"
)
SPEC = importlib.util.spec_from_file_location("deployment_authority_study", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
study = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = study
SPEC.loader.exec_module(study)

SHA = "a" * 40


def _write_case(tmp_path: Path, *, sha: str = SHA) -> Path:
    evidence = {
        "schema_version": 1,
        "provider": "gcp",
        "source": "reviewed-test-evidence",
        "workloads": [],
        "iam_bindings": [],
    }
    truth = {
        "schema_version": 1,
        "case_id": "natural-001",
        "reviewed": True,
        "security_ground_truth": {
            "runtime_effectiveness": "not_verified",
            "agents": [
                {
                    "agent": "support",
                    "identity": "support@prod.iam.gserviceaccount.com",
                    "classification": "aligned",
                    "required": {
                        "capabilities": ["tickets.read"],
                        "roles": ["roles/viewer"],
                        "permissions": ["tickets.read"],
                    },
                    "deployed": {
                        "roles": ["roles/viewer"],
                        "permissions": ["tickets.read"],
                    },
                    "excess": {"roles": [], "permissions": []},
                    "missing": {"roles": [], "permissions": []},
                    "unresolved": [],
                }
            ],
        },
        "expected_horustrace": {
            "runtime_effectiveness": "not_verified",
            "agents": [
                {
                    "agent": "support",
                    "identity": "support@prod.iam.gserviceaccount.com",
                    "status": "aligned",
                    "required": {
                        "roles": ["roles/viewer"],
                        "permissions": ["tickets.read"],
                    },
                    "deployed": {
                        "roles": ["roles/viewer"],
                        "permissions": ["tickets.read"],
                    },
                    "conditional_roles": [],
                    "conditional_permissions": [],
                    "excess": {"roles": [], "permissions": []},
                    "missing": {"roles": [], "permissions": []},
                    "unresolved": [],
                }
            ],
        },
        "evidence": {
            "application": [
                {
                    "path": "agent.py",
                    "rationale": "Reviewed tool authority.",
                }
            ],
            "infrastructure": [
                {
                    "path": "iam.tf",
                    "rationale": "Reviewed IAM binding.",
                }
            ],
        },
    }
    (tmp_path / "deployment.yaml").write_text(
        yaml.safe_dump(evidence),
        encoding="utf-8",
    )
    (tmp_path / "truth.yaml").write_text(
        yaml.safe_dump(truth),
        encoding="utf-8",
    )
    cohort = {
        "schema_version": 1,
        "study": "deployment-authority-v08",
        "cases": [
            {
                "case_id": "natural-001",
                "kind": "natural",
                "provider": "gcp",
                "framework": "google-adk",
                "application": {
                    "repo": "example/app",
                    "sha": sha,
                },
                "infrastructure": {
                    "repo": "example/infra",
                    "sha": SHA,
                    "path": "terraform",
                },
                "deployment_evidence": "deployment.yaml",
                "ground_truth": "truth.yaml",
            }
        ],
    }
    path = tmp_path / "cohort.yaml"
    path.write_text(yaml.safe_dump(cohort), encoding="utf-8")
    return path


def test_empty_cohort_is_valid(tmp_path: Path) -> None:
    path = tmp_path / "cohort.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "study": "deployment-authority-v08",
                "cases": [],
            }
        ),
        encoding="utf-8",
    )
    assert study.load_cohort(path) == []


def test_case_contract_requires_exact_commit_sha(tmp_path: Path) -> None:
    path = _write_case(tmp_path, sha="main")
    with pytest.raises(study.StudyError, match="40-character"):
        study.load_cohort(path)


def test_ground_truth_contract_loads_reviewed_case(tmp_path: Path) -> None:
    path = _write_case(tmp_path)
    case = study.load_cohort(path)[0]
    truth = study.validate_case_inputs(case)
    assert truth["reviewed"] is True
    assert truth["security_ground_truth"]["agents"][0]["classification"] == "aligned"
    assert truth["expected_horustrace"]["agents"][0]["status"] == "aligned"


def test_reconcile_command_includes_declared_authority_source() -> None:
    command = study.build_reconcile_command(
        Path("/tmp/app"),
        Path("/tmp/evidence.yaml"),
        Path("/tmp/infra"),
    )
    assert command == [
        "horustrace",
        "reconcile",
        "/tmp/app",
        "--deployment-evidence",
        "/tmp/evidence.yaml",
        "--format",
        "json",
        "--authority-source",
        "/tmp/infra",
    ]


def _reviewed_truth(
    expected_status: str = "aligned",
    security_classification: str = "aligned",
) -> dict:
    common = {
        "agent": "support",
        "identity": "support@prod.iam.gserviceaccount.com",
        "required": {
            "roles": ["roles/viewer"],
            "permissions": ["tickets.read"],
        },
        "deployed": {
            "roles": ["roles/viewer"],
            "permissions": ["tickets.read"],
        },
        "excess": {"roles": [], "permissions": []},
        "missing": {"roles": [], "permissions": []},
        "unresolved": [],
    }
    return {
        "security_ground_truth": {
            "agents": [
                {
                    **common,
                    "classification": security_classification,
                    "required": {
                        **common["required"],
                        "capabilities": ["tickets.read"],
                    },
                }
            ]
        },
        "expected_horustrace": {
            "agents": [
                {
                    **common,
                    "status": expected_status,
                    "conditional_roles": [],
                    "conditional_permissions": [],
                }
            ]
        },
    }

def _aligned_report() -> dict:
    return {
        "runtime_effectiveness": "not_verified",
        "deployed_identity": {
            "relationships": [
                {
                    "agent": "support",
                    "identity": "support@prod.iam.gserviceaccount.com",
                }
            ]
        },
        "reconciliation": {
            "agents": [
                {
                    "agent": "support",
                    "status": "aligned",
                    "required": {
                        "roles": ["roles/viewer"],
                        "permissions": ["tickets.read"],
                    },
                    "deployed": {
                        "roles": ["roles/viewer"],
                        "permissions": ["tickets.read"],
                        "conditional_roles": [],
                        "conditional_permissions": [],
                    },
                    "excess": {"roles": [], "permissions": []},
                    "missing": {"roles": [], "permissions": []},
                    "unresolved": [],
                }
            ]
        },
    }


def test_evaluate_report_matches_reviewed_authority() -> None:
    assert study.evaluate_report(
        _aligned_report(),
        _reviewed_truth(),
    )["passed"] is True


def test_evaluate_report_records_classification_mismatch() -> None:
    evaluation = study.evaluate_report(
        _aligned_report(),
        _reviewed_truth(expected_status="excess_authority"),
    )
    assert evaluation["passed"] is False
    assert any("status" in failure for failure in evaluation["failures"])


def test_security_ground_truth_is_independent_from_expected_output() -> None:
    evaluation = study.evaluate_report(
        _aligned_report(),
        _reviewed_truth(
            expected_status="aligned",
            security_classification="excess_authority",
        ),
    )
    assert evaluation["passed"] is True
    assert evaluation["agents"][0]["security_classification"] == "excess_authority"

    report = study.aggregate(
        [
            {
                "passed": True,
                "evaluation": evaluation,
            }
        ]
    )
    assert report["expected_output_confusion_matrix"]["aligned"]["aligned"] == 1
    assert (
        report["security_classification_confusion_matrix"]["excess_authority"]["aligned"]
        == 1
    )
    assert report["summary"]["security_classification_matches"] == 0
    assert report["summary"]["security_classification_mismatches"] == 1


def test_ground_truth_requires_independent_security_section(tmp_path: Path) -> None:
    path = _write_case(tmp_path)
    case = study.load_cohort(path)[0]
    truth = yaml.safe_load(case.ground_truth.read_text(encoding="utf-8"))
    truth.pop("security_ground_truth")
    case.ground_truth.write_text(yaml.safe_dump(truth), encoding="utf-8")

    with pytest.raises(study.StudyError, match="security_ground_truth"):
        study.validate_case_inputs(case)


def test_case_validation_uses_full_deployment_evidence_contract(tmp_path: Path) -> None:
    path = _write_case(tmp_path)
    case = study.load_cohort(path)[0]
    evidence = yaml.safe_load(case.deployment_evidence.read_text(encoding="utf-8"))
    evidence["unsupported_field"] = "must fail closed"
    case.deployment_evidence.write_text(yaml.safe_dump(evidence), encoding="utf-8")

    with pytest.raises(study.StudyError, match="invalid Deployment Evidence v1"):
        study.validate_case_inputs(case)
