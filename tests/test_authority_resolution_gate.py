from pathlib import Path

from horustrace import cli
from horustrace.models import Agent, Graph, Tool


def _unresolved_graph(count: int) -> Graph:
    return Graph(
        agents=[
            Agent(
                name="agent",
                tools=[
                    Tool(
                        name=f"tool_{index}",
                        kind="function",
                        capabilities={"data.read"},
                    )
                    for index in range(count)
                ],
            )
        ]
    )


def test_scan_max_unresolved_authority_gate_fails_when_budget_exceeded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_unresolved_graph(2), []))

    result = cli.main(
        [
            "scan",
            str(tmp_path),
            "--fail-on",
            "none",
            "--max-unresolved-authority",
            "1",
        ]
    )

    assert result == 1


def test_scan_max_unresolved_authority_gate_allows_budget(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: (_unresolved_graph(2), []))

    result = cli.main(
        [
            "scan",
            str(tmp_path),
            "--fail-on",
            "none",
            "--max-unresolved-authority",
            "2",
        ]
    )

    assert result == 0


def test_diff_authority_regression_gate_is_change_aware(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "build_git_diff",
        lambda *_args: {
            "base": {"analysis_incomplete": False},
            "head": {"analysis_incomplete": False},
            "authority_resolution": {"regressed": True},
            "authority_policy_delta": {
                "introduced_violations": [],
                "contract_weakenings": [],
            },
            "findings": {"introduced": [], "worsened": []},
        },
    )

    result = cli.main(
        [
            "diff",
            "base..head",
            "--repo",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "none",
            "--fail-on-authority-regression",
        ]
    )

    assert result == 1


def test_diff_authority_regression_is_opt_in(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "build_git_diff",
        lambda *_args: {
            "base": {"analysis_incomplete": False},
            "head": {"analysis_incomplete": False},
            "authority_resolution": {"regressed": True},
            "authority_policy_delta": {
                "introduced_violations": [],
                "contract_weakenings": [],
            },
            "findings": {"introduced": [], "worsened": []},
        },
    )

    result = cli.main(
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
