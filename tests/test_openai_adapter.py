from pathlib import Path

from horustrace.scanner import scan


def test_detects_shell_without_approval(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, ShellTool
agent = Agent(name='Ops', tools=[ShellTool()])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)

    assert len(graph.agents) == 1
    assert any(f.rule_id == "AGT020" for f in findings)


def test_approval_suppresses_shell_rule(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, ShellTool
agent = Agent(name='Ops', tools=[ShellTool(needs_approval=True)])
""",
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    assert not any(f.rule_id == "AGT020" for f in findings)


def test_resolves_named_tool_list(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, ShellTool
shell = ShellTool()
tools = [shell]
agent = Agent(name='Ops', tools=tools)
""",
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    assert graph.agents[0].tools[0].name == "shell"
    assert any(f.rule_id == "AGT020" for f in findings)


def test_apply_patch_is_state_changing(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, ApplyPatchTool
agent = Agent(name='Coder', tools=[ApplyPatchTool()])
""",
        encoding="utf-8",
    )
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "AGT022" for f in findings)
