from pathlib import Path

from horustrace.scanner import scan


def test_openai_handoffs_project_to_delegation_edges(tmp_path: Path) -> None:
    (tmp_path / "agents.py").write_text(
        """
from agents import Agent

billing = Agent(name="billing")
triage = Agent(name="triage", handoffs=[billing])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    triage = next(agent for agent in graph.agents if agent.name == "triage")
    assert triage.metadata["delegates_to"] == ["billing"]
    assert graph.adg is not None
    kinds = {edge.kind for edge in graph.adg.edges}
    assert "DELEGATES_TO" in kinds


def test_langgraph_memory_is_first_class_adg_node(tmp_path: Path) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import StateGraph

memory = SqliteSaver()
workflow = StateGraph(dict)
app = workflow.compile(checkpointer=memory)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(agent for agent in graph.agents if agent.metadata.get("framework") == "langgraph")
    assert agent.metadata["memory"][0]["persistent"] is True
    assert graph.adg is not None
    memories = [node for node in graph.adg.nodes if node.kind == "memory"]
    assert len(memories) == 1
    assert memories[0].attributes["persistent"] is True


def test_static_flow_projects_data_flow_edges_to_adg(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import subprocess
from agents import Agent, function_tool

@function_tool
def run_user_command():
    value = input("command")
    subprocess.run(value, shell=True)

agent = Agent(name="ops", tools=[run_user_command])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert graph.flow_paths
    assert graph.adg is not None
    assert any(edge.kind == "DATA_FLOWS_TO" for edge in graph.adg.edges)



def test_delegation_projects_reachable_child_identity_authority(tmp_path: Path) -> None:
    (tmp_path / "agents.py").write_text(
        """
from agents import Agent

billing = Agent(name="billing")
triage = Agent(name="triage", handoffs=[billing])
""",
        encoding="utf-8",
    )
    (tmp_path / "horustrace.manifest.yaml").write_text(
        """
version: 1
agents:
  - name: billing
    identities:
      - name: billing-reader
        provider: gcp
        roles: [roles/storage.objectViewer]
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert graph.adg is not None
    nodes = {node.node_id: node for node in graph.adg.nodes}
    authority_edges = [
        edge for edge in graph.adg.edges if edge.kind == "CAN_REACH_AUTHORITY"
    ]
    assert len(authority_edges) == 1
    edge = authority_edges[0]
    assert nodes[edge.source].name == "triage"
    assert nodes[edge.target].name == "billing-reader"
    assert edge.attributes["via_agent"] == "billing"
