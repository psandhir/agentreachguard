from pathlib import Path

from horustrace.scanner import _classify_source_context


def test_source_context_classification() -> None:
    assert _classify_source_context(Path("src/app/agent.py")) == "runtime"
    assert _classify_source_context(Path("backend/tests/test_agent.py")) == "test"
    assert _classify_source_context(Path("examples/demo_agent.py")) == "example"
    assert _classify_source_context(Path("adk_training/lesson_01/agent.py")) == "tutorial"
    assert _classify_source_context(Path("notebooks/risky.ipynb")) == "notebook"
    assert _classify_source_context(Path("templates/agent.py")) == "template-generated"
    assert _classify_source_context(None) == "unknown"
