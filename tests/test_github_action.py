from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from horustrace.github_action import (
    GitHubActionError,
    ensure_commit_available,
    prepare_pull_request_diff,
    resolve_pull_request_revisions,
)


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _commit(repo: Path, name: str, content: str) -> str:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "-m", f"write {name}")
    return _git(repo, "rev-parse", "HEAD")


def _init_repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "horustrace@example.test")
    _git(repo, "config", "user.name", "HorusTrace Tests")
    base = _commit(repo, "agent.py", "base\n")
    head = _commit(repo, "agent.py", "head\n")
    return repo, base, head


def _write_event(
    path: Path,
    *,
    base: str,
    head: str,
    number: int = 42,
) -> Path:
    path.write_text(
        json.dumps(
            {
                "number": number,
                "pull_request": {
                    "base": {"sha": base},
                    "head": {"sha": head},
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def test_resolve_pull_request_revisions_from_event(tmp_path: Path) -> None:
    _, base, head = _init_repo(tmp_path)
    event = _write_event(tmp_path / "event.json", base=base, head=head, number=17)

    revisions = resolve_pull_request_revisions(event_path=event)

    assert revisions.base_sha == base
    assert revisions.head_sha == head
    assert revisions.number == 17


def test_explicit_revisions_require_both_values(tmp_path: Path) -> None:
    _, base, _ = _init_repo(tmp_path)

    with pytest.raises(GitHubActionError, match="provided together"):
        resolve_pull_request_revisions(
            event_path=None,
            base_sha=base,
            head_sha="",
        )


def test_explicit_revisions_reject_non_sha_values() -> None:
    with pytest.raises(GitHubActionError, match="full hexadecimal commit SHA"):
        resolve_pull_request_revisions(
            event_path=None,
            base_sha="main",
            head_sha="HEAD",
        )


def test_non_pull_request_event_fails_closed(tmp_path: Path) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"ref": "refs/heads/main"}), encoding="utf-8")

    with pytest.raises(GitHubActionError, match="pull_request event"):
        resolve_pull_request_revisions(event_path=event)


def test_prepare_pull_request_diff_uses_existing_commits(tmp_path: Path) -> None:
    repo, base, head = _init_repo(tmp_path)
    event = _write_event(tmp_path / "event.json", base=base, head=head)

    root, revisions = prepare_pull_request_diff(repo, event_path=event)

    assert root == repo.resolve()
    assert revisions.base_sha == base
    assert revisions.head_sha == head


def test_ensure_commit_available_fetches_exact_missing_commit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init")
    _git(source, "config", "user.email", "horustrace@example.test")
    _git(source, "config", "user.name", "HorusTrace Tests")
    base = _commit(source, "agent.py", "base\n")
    head = _commit(source, "feature.py", "head\n")
    _git(source, "branch", "feature", head)
    _git(source, "reset", "--hard", base)

    remote = tmp_path / "remote.git"
    subprocess.run(
        ["git", "clone", "--bare", str(source), str(remote)],
        check=True,
        capture_output=True,
        text=True,
    )

    checkout = tmp_path / "checkout"
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--depth=1",
            "--branch",
            "master",
            remote.as_uri(),
            str(checkout),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert _git(checkout, "rev-parse", "HEAD") == base

    probe = subprocess.run(
        ["git", "-C", str(checkout), "cat-file", "-e", f"{head}^{{commit}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode != 0

    ensure_commit_available(checkout, head)

    assert _git(checkout, "rev-parse", "--verify", f"{head}^{{commit}}") == head


def test_ensure_commit_available_uses_pull_request_head_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    expected = "a" * 40
    state = {"available": False}
    calls: list[str] = []

    monkeypatch.setattr(
        "horustrace.github_action._has_commit",
        lambda _repo, _sha: state["available"],
    )

    def fake_fetch(_repo: Path, ref: str) -> bool:
        calls.append(ref)
        if ref == "refs/pull/42/head":
            state["available"] = True
            return True
        return False

    monkeypatch.setattr("horustrace.github_action._fetch", fake_fetch)
    monkeypatch.setattr(
        "horustrace.github_action.resolve_commit",
        lambda _repo, _ref: expected,
    )

    ensure_commit_available(
        repo,
        expected,
        pull_request_number=42,
        allow_pull_request_head_fallback=True,
    )

    assert calls == [expected, "refs/pull/42/head"]
