from pathlib import Path

from horustrace.scanner import scan


def test_adk_project_descriptor_does_not_create_duplicate_agent(tmp_path: Path) -> None:
    (tmp_path / "adk.yaml").write_text(
        """
name: agentGemini
version: 1.0.0

agent:
  entry_point: agent.py
  root_agent: root_agent

model:
  name: gemini-2.0-flash
  temperature: 0.7
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import LlmAgent

funnel_agent = LlmAgent(
    name="FunnelAgent",
    model="gemini-2.0-flash",
    instruction="Help the user.",
)
root_agent = funnel_agent
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    names = [agent.name for agent in graph.agents]
    assert "FunnelAgent" in names
    assert "agentGemini" not in names


def test_root_agent_yaml_remains_an_agent_config(tmp_path: Path) -> None:
    (tmp_path / "root_agent.yaml").write_text(
        """
name: support_agent
model: gemini-2.0-flash
instruction: Help the user.
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert any(agent.name == "support_agent" for agent in graph.agents)
