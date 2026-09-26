from pathlib import Path

from horustrace.scanner import scan


def test_adk_repository_enrichment_does_not_duplicate_source_agent_roots(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import LlmAgent, SequentialAgent

funnel_agent = LlmAgent(
    name="FunnelAgent",
    model="gemini-2.0-flash",
    instruction="help",
    tools=[],
)
root_agent = funnel_agent
""",
        encoding="utf-8",
    )

    package = tmp_path / "agentGemini"
    package.mkdir()
    (package / "__init__.py").write_text(
        "from .agent import root_agent\n",
        encoding="utf-8",
    )
    (package / "agent.py").write_text(
        """
from google.genai.adk import Agent

root_agent = Agent(
    name="AgroAsesorIA",
    model="gemini-2.0-flash",
    instruction="help",
    tools=[],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    observed = [
        (
            agent.name,
            str(agent.location.path.relative_to(tmp_path)) if agent.location else None,
            agent.location.line if agent.location else None,
            agent.metadata.get("repository_resolved"),
            agent.metadata.get("instance_key"),
        )
        for agent in graph.agents
    ]
    assert observed == [
        ("FunnelAgent", "agent.py", 4, True, None),
        ("AgroAsesorIA", "agentGemini/agent.py", 4, True, None),
    ]
