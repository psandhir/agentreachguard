from pathlib import Path

from horustrace.scanner import scan


def test_unreadable_directory_becomes_coverage_diagnostic(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5")
""",
        encoding="utf-8",
    )
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "secret.py").write_text("value = 1\n", encoding="utf-8")

    original_iterdir = Path.iterdir

    def guarded_iterdir(path: Path):
        if path == blocked:
            raise PermissionError("denied")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", guarded_iterdir)

    graph, _ = scan(tmp_path)

    diagnostic = next(
        item
        for item in graph.coverage.diagnostics
        if item.kind == "unreadable_path"
    )
    assert diagnostic.diagnostic_id == "ARG-COV-019"
    assert diagnostic.details == {
        "path": "blocked",
        "operation": "list_directory",
        "exception_type": "PermissionError",
    }
    assert graph.coverage.incomplete is True
    assert any(agent.name == "agent" for agent in graph.agents)


def test_broken_symlink_does_not_abort_scan(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5")
""",
        encoding="utf-8",
    )
    broken = tmp_path / "broken.py"
    try:
        broken.symlink_to(tmp_path / "missing.py")
    except (OSError, NotImplementedError):
        return

    graph, _ = scan(tmp_path)

    diagnostic = next(
        item
        for item in graph.coverage.diagnostics
        if item.kind == "unreadable_path"
    )
    assert diagnostic.details["path"] == "broken.py"
    assert diagnostic.details["operation"] == "inspect_path"
    assert diagnostic.details["exception_type"] == "FileNotFoundError"
    assert any(agent.name == "agent" for agent in graph.agents)


def test_directory_symlink_is_not_recursed(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5")
""",
        encoding="utf-8",
    )
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        return

    graph, _ = scan(tmp_path)

    # The real directory is scanned exactly once; the symlink is skipped.
    assert len([agent for agent in graph.agents if agent.name == "agent"]) == 1
