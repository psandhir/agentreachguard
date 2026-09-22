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


def test_openai_mcp_static_tool_filter_is_normalized(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStreamableHttp, create_static_tool_filter
server = MCPServerStreamableHttp(
    params={"url": "https://mcp.example.com", "headers": {"Authorization": "Bearer x"}},
    tool_filter=create_static_tool_filter(
        allowed_tool_names=["search_messages", "read_thread"],
        blocked_tool_names=["send_message"],
    ),
)
agent = Agent(name="Reader", mcp_servers=[server])
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    server = graph.agents[0].mcp_servers[0]
    assert server.allowed_tools == ["search_messages", "read_thread"]
    assert server.denied_tools == ["send_message"]
    assert not any(f.rule_id == "AGT032" for f in findings)


def test_openai_runtime_clone_binds_mcp_server(tmp_path: Path) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, Runner
from agents.mcp import MCPServerStreamableHttp
agent = Agent(name="Starter")
async def run():
    server = MCPServerStreamableHttp(
        params={"url": "https://mcp.example.com", "headers": {"Authorization": "Bearer x"}},
    )
    async with server:
        agent_with_mcp = agent.clone(mcp_servers=[server])
        return await Runner.run(agent_with_mcp, input="hello")
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    assert len(graph.agents) == 1
    assert [server.name for server in graph.agents[0].mcp_servers] == ["server"]
    assert graph.agents[0].metadata["runtime_clone_mcp"] is True
    assert any(f.rule_id == "AGT032" for f in findings)
