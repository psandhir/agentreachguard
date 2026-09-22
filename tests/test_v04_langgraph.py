from pathlib import Path

from horustrace.scanner import scan


def test_langgraph_nodes_and_control_edges_project_to_adg(tmp_path: Path) -> None:
    (tmp_path / "workflow.py").write_text(
        """
from langgraph.graph import StateGraph, END


def fetch(state):
    return state


def execute(state):
    return state

workflow = StateGraph(dict)
workflow.add_node("fetch", fetch)
workflow.add_node("execute", execute)
workflow.add_edge("fetch", "execute")
workflow.add_edge("execute", END)
app = workflow.compile()
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(agent for agent in graph.agents if agent.metadata.get("framework") == "langgraph")
    assert {tool.name for tool in agent.tools} == {"fetch", "execute"}
    assert ("fetch", "execute") in agent.metadata["control_edges"]
    assert graph.adg is not None
    assert any(edge.kind == "CONTROL_FLOWS_TO" for edge in graph.adg.edges)


def test_langgraph_re_compile_is_not_process_execution(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """import re
from langgraph.graph import StateGraph

def validate_email(state):
    pattern = re.compile(r"^[^@]+@[^@]+$")
    return {"valid": bool(pattern.match(state["email"]))}

workflow = StateGraph(dict)
workflow.add_node("validate_email", validate_email)
""",
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    tool = next(t for a in graph.agents for t in a.tools if t.name == "validate_email")
    assert "process.execute" not in tool.capabilities
    assert not any(f.rule_id == "AGT020" for f in findings)



def test_langgraph_human_interrupt_gates_downstream_mutation(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """from langgraph.graph import StateGraph
from langgraph.types import interrupt
import requests

def review(state):
    response = interrupt([{"action": "review"}])[0]
    return {"approved": response.get("type") == "accept"}

def apply_change(state):
    requests.post("https://example.com/issues", json=state)

workflow = StateGraph(dict)
workflow.add_node("review", review)
workflow.add_node("apply_change", apply_change)
workflow.add_edge("review", "apply_change")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(a for a in graph.agents if a.metadata.get("framework") == "langgraph")
    review = next(t for t in agent.tools if t.name == "review")
    mutation = next(t for t in agent.tools if t.name == "apply_change")

    assert review.metadata.get("approval_control") is True
    assert mutation.approval is True
    assert mutation.metadata.get("approval_gated_by") == "review"
    assert mutation.metadata.get("approval_scope") == "execution_gate"


def test_langgraph_interrupt_without_approval_semantics_does_not_gate(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """from langgraph.graph import StateGraph
from langgraph.types import interrupt
import requests

def pause(state):
    interrupt("continue?")

def apply_change(state):
    requests.post("https://example.com/issues", json=state)

workflow = StateGraph(dict)
workflow.add_node("pause", pause)
workflow.add_node("apply_change", apply_change)
workflow.add_edge("pause", "apply_change")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(a for a in graph.agents if a.metadata.get("framework") == "langgraph")
    mutation = next(t for t in agent.tools if t.name == "apply_change")

    assert mutation.approval is not True
    assert "approval_gated_by" not in mutation.metadata
