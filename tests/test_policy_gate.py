import json
from pathlib import Path

import yaml

from horustrace.cli import main


def _report(
    *,
    introduced_violations: list[dict] | None = None,
    introduced_unresolved: list[dict] | None = None,
    analysis_incomplete: bool = False,
) -> dict:
    return {
        "base": {"analysis_incomplete": analysis_incomplete},
        "head": {"analysis_incomplete": analysis_incomplete},
        "findings": {
            "introduced": [],
            "worsened": [],
        },
        "authority_policy_delta": {
            "introduced_violations": introduced_violations or [],
            "introduced_unresolved": introduced_unresolved or [],
        },
    }


def test_diff_policy_gate_fails_only_on_introduced_violation(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        "horustrace.cli.build_git_diff",
        lambda *_args: _report(
            introduced_violations=[
                {
                    "result_id": "contract-violation-v1:test",
                    "clause": "allow.capabilities",
                }
            ]
        ),
    )

    result = main(
        [
            "diff",
            "base..head",
            "--repo",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "none",
            "--fail-on-policy-violation",
        ]
    )

    assert result == 2
    json.loads(capsys.readouterr().out)


def test_diff_policy_violation_does_not_fail_without_opt_in(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "horustrace.cli.build_git_diff",
        lambda *_args: _report(
            introduced_violations=[
                {
                    "result_id": "contract-violation-v1:test",
                    "clause": "allow.capabilities",
                }
            ]
        ),
    )

    result = main(
        [
            "diff",
            "base..head",
            "--repo",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "none",
        ]
    )

    assert result == 0


def test_diff_policy_gate_ignores_unresolved_only_change(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "horustrace.cli.build_git_diff",
        lambda *_args: _report(
            introduced_unresolved=[
                {
                    "result_id": "contract-unresolved-v1:test",
                    "clause": "allow.identities",
                }
            ]
        ),
    )

    result = main(
        [
            "diff",
            "base..head",
            "--repo",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "none",
            "--fail-on-policy-violation",
        ]
    )

    assert result == 0


def test_diff_strict_incomplete_analysis_precedes_policy_gate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "horustrace.cli.build_git_diff",
        lambda *_args: _report(
            introduced_violations=[
                {"result_id": "contract-violation-v1:test"}
            ],
            analysis_incomplete=True,
        ),
    )

    result = main(
        [
            "diff",
            "base..head",
            "--repo",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "none",
            "--fail-on-policy-violation",
            "--strict",
        ]
    )

    assert result == 1


def test_action_policy_gate_is_opt_in_and_passes_cli_flag() -> None:
    root = Path(__file__).resolve().parents[1]
    action_path = root / "action.yml"
    document = yaml.safe_load(action_path.read_text(encoding="utf-8"))

    gate = document["inputs"]["fail-on-policy-violation"]
    assert gate["required"] is False
    assert gate["default"] == "false"

    diff_step = next(
        step
        for step in document["runs"]["steps"]
        if step.get("id") == "diff"
    )
    assert (
        diff_step["env"]["DIFF_FAIL_ON_POLICY_VIOLATION"]
        == "${{ inputs.fail-on-policy-violation }}"
    )
    script = diff_step["run"]
    assert "fail-on-policy-violation must be true or false" in script
    assert 'diff_args+=(--fail-on-policy-violation)' in script
