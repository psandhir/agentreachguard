from pathlib import Path

import pytest

import horustrace.scanner as scanner_module
from horustrace.scanner import ScannerError, scan


def test_irrelevant_repository_payload_does_not_consume_candidate_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(scanner_module, "MAX_FILES_VISITED", 2)

    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent

agent = Agent("openai:gpt-5")
""",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
version = "0.1.0"

[project.scripts]
demo = "agent:main"
""",
        encoding="utf-8",
    )

    vendored = tmp_path / "opentitan"
    vendored.mkdir()
    for index in range(25):
        (vendored / f"rtl_{index}.sv").write_text(
            "module demo; endmodule\n",
            encoding="utf-8",
        )
        (vendored / f"driver_{index}.c").write_text(
            "int main(void) { return 0; }\n",
            encoding="utf-8",
        )

    graph, _ = scan(tmp_path)

    assert any(agent.name == "agent" for agent in graph.agents)


def test_supported_analysis_candidates_still_respect_file_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(scanner_module, "MAX_FILES_VISITED", 2)

    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(ScannerError, match="2-candidate safety limit"):
        scan(tmp_path)


def test_repository_entry_traversal_remains_bounded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(scanner_module, "MAX_REPOSITORY_ENTRIES_VISITED", 3)

    for index in range(4):
        (tmp_path / f"payload_{index}.sv").write_text(
            "module demo; endmodule\n",
            encoding="utf-8",
        )

    with pytest.raises(ScannerError, match="3-entry safety limit"):
        scan(tmp_path)
