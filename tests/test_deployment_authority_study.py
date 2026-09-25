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
        "expected": {
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
    assert truth["expected"]["agents"][0]["status"] == "aligned"


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


def _reviewed_truth(status: str = "aligned") -> dict:
    return {
        "expected": {
            "agents": [
                {
                    "agent": "support",
                    "identity": "support@prod.iam.gserviceaccount.com",
                    "status": status,
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
            ]
        }
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
        _reviewed_truth("excess_authority"),
    )
    assert evaluation["passed"] is False
    assert any("status" in failure for failure in evaluation["failures"])
