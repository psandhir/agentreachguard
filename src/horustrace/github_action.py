"""GitHub Actions integration for immutable pull-request change analysis."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from horustrace.git_snapshot import GitSnapshotError, git_root, resolve_commit

_GITHUB_COMMIT_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_MAX_EVENT_BYTES = 10 * 1024 * 1024


class GitHubActionError(ValueError):
    """GitHub Actions metadata or repository preparation is invalid."""


@dataclass(frozen=True, slots=True)
class PullRequestRevisions:
    base_sha: str
    head_sha: str
    number: int | None = None


def _validate_sha(value: str, *, field: str) -> str:
    sha = value.strip().lower()
    if not _GITHUB_COMMIT_RE.fullmatch(sha):
        raise GitHubActionError(f"{field} must be a full hexadecimal commit SHA")
    return sha


def _read_event(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise GitHubActionError(f"cannot read GitHub event payload: {path}") from exc
    if size > _MAX_EVENT_BYTES:
        raise GitHubActionError("GitHub event payload exceeds the 10 MiB safety limit")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubActionError("GitHub event payload is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise GitHubActionError("GitHub event payload must be a JSON object")
    return raw


def _pr_number(value: object) -> int | None:
    if type(value) is not int or value <= 0:
        return None
    return value


def resolve_pull_request_revisions(
    *,
    event_path: Path | None,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> PullRequestRevisions:
    """Resolve immutable comparison commits from explicit input or a PR event."""
    explicit_base = (base_sha or "").strip()
    explicit_head = (head_sha or "").strip()
    if bool(explicit_base) != bool(explicit_head):
        raise GitHubActionError("base-sha and head-sha must be provided together")
    if explicit_base and explicit_head:
        return PullRequestRevisions(
            base_sha=_validate_sha(explicit_base, field="base-sha"),
            head_sha=_validate_sha(explicit_head, field="head-sha"),
        )

    if event_path is None:
        raise GitHubActionError(
            "diff mode requires a pull_request event or explicit base-sha/head-sha"
        )
    event = _read_event(event_path)
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        raise GitHubActionError(
            "diff mode requires a pull_request event or explicit base-sha/head-sha"
        )

    base = pull_request.get("base")
    head = pull_request.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise GitHubActionError("pull_request event is missing base/head metadata")

    base_value = base.get("sha")
    head_value = head.get("sha")
    if not isinstance(base_value, str) or not isinstance(head_value, str):
        raise GitHubActionError("pull_request event is missing immutable base/head SHAs")

    return PullRequestRevisions(
        base_sha=_validate_sha(base_value, field="pull_request.base.sha"),
        head_sha=_validate_sha(head_value, field="pull_request.head.sha"),
        number=_pr_number(event.get("number")),
    )


def _run_git(repo: Path, args: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise GitHubActionError("git executable is not available") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitHubActionError("git command exceeded the safety timeout") from exc


def _has_commit(repo: Path, sha: str) -> bool:
    result = _run_git(repo, ["cat-file", "-e", f"{sha}^{{commit}}"], timeout=30)
    return result.returncode == 0


def _fetch(repo: Path, ref: str) -> bool:
    result = _run_git(
        repo,
        ["fetch", "--no-tags", "--depth=1", "origin", ref],
    )
    return result.returncode == 0


def ensure_commit_available(
    repo: Path,
    sha: str,
    *,
    pull_request_number: int | None = None,
    allow_pull_request_head_fallback: bool = False,
) -> None:
    """Make an immutable commit available without checking it out."""
    expected = _validate_sha(sha, field="commit")
    if _has_commit(repo, expected):
        return

    fetched = _fetch(repo, expected)
    if (
        not fetched
        and allow_pull_request_head_fallback
        and pull_request_number is not None
    ):
        fetched = _fetch(repo, f"refs/pull/{pull_request_number}/head")

    if not fetched or not _has_commit(repo, expected):
        raise GitHubActionError(f"unable to fetch required commit: {expected}")

    try:
        resolved = resolve_commit(repo, expected)
    except GitSnapshotError as exc:
        raise GitHubActionError(str(exc)) from exc
    if resolved != expected:
        raise GitHubActionError("fetched revision did not resolve to the expected commit")


def prepare_pull_request_diff(
    repo: Path,
    *,
    event_path: Path | None,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> tuple[Path, PullRequestRevisions]:
    """Resolve PR commits and ensure both are locally available for git archive."""
    try:
        root = git_root(repo)
    except GitSnapshotError as exc:
        raise GitHubActionError(str(exc)) from exc

    revisions = resolve_pull_request_revisions(
        event_path=event_path,
        base_sha=base_sha,
        head_sha=head_sha,
    )
    ensure_commit_available(root, revisions.base_sha)
    ensure_commit_available(
        root,
        revisions.head_sha,
        pull_request_number=revisions.number,
        allow_pull_request_head_fallback=True,
    )
    return root, revisions


def _write_github_output(path: Path, values: dict[str, str]) -> None:
    try:
        with path.open("a", encoding="utf-8") as output:
            for key, value in values.items():
                if "\n" in value or "\r" in value:
                    raise GitHubActionError("GitHub Action output values must be single-line")
                output.write(f"{key}={value}\n")
    except OSError as exc:
        raise GitHubActionError(f"cannot write GitHub Action outputs: {path}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m horustrace.github_action",
        description="Prepare immutable GitHub pull-request revisions for HorusTrace diff.",
    )
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--event-path", type=Path)
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--head-sha", default="")
    parser.add_argument("--output-file", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    event_path = args.event_path
    if event_path is None:
        raw_event_path = os.environ.get("GITHUB_EVENT_PATH", "").strip()
        event_path = Path(raw_event_path) if raw_event_path else None

    try:
        root, revisions = prepare_pull_request_diff(
            args.repo,
            event_path=event_path,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
        )
        values = {
            "repo_root": root.as_posix(),
            "base_sha": revisions.base_sha,
            "head_sha": revisions.head_sha,
            "revision_range": f"{revisions.base_sha}..{revisions.head_sha}",
        }
        output_file = args.output_file
        if output_file is None:
            raw_output = os.environ.get("GITHUB_OUTPUT", "").strip()
            output_file = Path(raw_output) if raw_output else None
        if output_file is not None:
            _write_github_output(output_file, values)
        else:
            print(json.dumps(values, sort_keys=True))
    except GitHubActionError as exc:
        print(f"horustrace-action: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
