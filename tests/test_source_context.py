import json
from pathlib import Path

from horustrace.cli import main
from horustrace.scanner import _classify_source_context


def test_source_context_classification() -> None:
    assert _classify_source_context(Path("src/app/agent.py")) == "runtime"
    assert _classify_source_context(Path("backend/tests/test_agent.py")) == "test"
    assert _classify_source_context(Path("examples/demo_agent.py")) == "example"
    assert _classify_source_context(Path("adk_training/lesson_01/agent.py")) == "tutorial"
    assert _classify_source_context(Path("notebooks/risky.ipynb")) == "notebook"
    assert _classify_source_context(Path("templates/agent.py")) == "template-generated"
    assert _classify_source_context(None) == "unknown"



def test_cli_excludes_findings_by_source_role_without_hiding_coverage(
    tmp_path: Path,
    capsys,
) -> None:
    runtime = tmp_path / "src"
    runtime.mkdir()
    (runtime / "agent.py").write_text(
        """
from agents import Agent, ShellTool
agent = Agent(name="runtime", tools=[ShellTool(needs_approval=False)])
""",
        encoding="utf-8",
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_agent.py").write_text(
        """
from agents import Agent, ShellTool
agent = Agent(name="test", tools=[ShellTool(needs_approval=False)])
""",
        encoding="utf-8",
    )

    assert main([
        "scan",
        str(tmp_path),
        "--format",
        "json",
        "--fail-on",
        "none",
        "--exclude-source-role",
        "test",
    ]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["summary"]["findings_by_source_context_before_filter"]["test"] > 0
    assert report["summary"]["excluded_findings_by_source_context"]["test"] > 0
    assert report["summary"]["findings_by_source_context"].get("test", 0) == 0
    assert report["configuration"]["effective"]["exclude_source_contexts"] == ["test"]
    assert all(item["source_context"] != "test" for item in report["findings"])
    assert report["coverage"]["files_scanned"] >= 2


def test_source_context_filter_does_not_clear_incomplete_coverage(
    tmp_path: Path,
    capsys,
) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_dynamic_mcp.py").write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStreamableHttp

def endpoint():
    return "https://example.test/mcp"

server = MCPServerStreamableHttp(params={"url": endpoint()})
agent = Agent(name="dynamic", mcp_servers=[server])
""",
        encoding="utf-8",
    )

    assert main([
        "scan",
        str(tmp_path),
        "--format",
        "json",
        "--fail-on",
        "none",
        "--exclude-source-context",
        "test",
    ]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["coverage"]["incomplete"] is True
    assert any(
        item["kind"] == "dynamic_mcp_endpoint"
        for item in report["coverage"]["diagnostics"]
    )


def test_cli_rejects_unknown_source_context(tmp_path: Path, capsys) -> None:
    assert main([
        "scan",
        str(tmp_path),
        "--exclude-source-context",
        "production",
    ]) == 1
    assert "unknown source context" in capsys.readouterr().err
