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



def test_langgraph_local_dict_update_is_not_persistent_data_write(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """from langgraph.graph import StateGraph

def review_issue(state):
    decision: dict[str, object] = {"approved": False}
    decision.update({"approved": True})
    return decision

workflow = StateGraph(dict)
workflow.add_node("review_issue", review_issue)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(t for a in graph.agents for t in a.tools if t.name == "review_issue")

    assert "data.write" not in tool.capabilities


def test_langgraph_state_update_remains_data_write(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """from langgraph.graph import StateGraph

def apply_update(state):
    state.update({"approved": True})
    return state

workflow = StateGraph(dict)
workflow.add_node("apply_update", apply_update)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    tool = next(t for a in graph.agents for t in a.tools if t.name == "apply_update")

    assert "data.write" in tool.capabilities


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
    assert graph.adg is not None
    assert any(node.kind == "approval_control" for node in graph.adg.nodes)
    assert any(edge.kind == "GUARDED_BY" for edge in graph.adg.edges)


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



def _write_langgraph_computer_action(tmp_path: Path, action: str) -> None:
    (tmp_path / "agent.py").write_text(
        f"""from langgraph.graph import StateGraph

def take_computer_action(state):
    instance.computer(action="{action}")

workflow = StateGraph(dict)
workflow.add_node("take_computer_action", take_computer_action)
""",
        encoding="utf-8",
    )


def test_langgraph_custom_computer_click_is_normalized(tmp_path: Path) -> None:
    _write_langgraph_computer_action(tmp_path, "click_mouse")

    graph, findings = scan(tmp_path)
    agent = next(a for a in graph.agents if a.metadata.get("framework") == "langgraph")
    tool = next(t for t in agent.tools if t.name == "take_computer_action")

    assert {"computer.control", "external.write"} <= tool.capabilities
    assert tool.metadata["computer_control_actions"] == ["click_mouse"]
    assert tool.metadata["computer_control_mutating"] is True
    assert tool.metadata["computer_control_readonly"] is False
    assert tool.metadata["computer_control_evidence"] == "call_shape"

    finding = next(f for f in findings if f.rule_id == "AGT023")
    assert finding.agent == "workflow"
    assert finding.location is not None
    assert finding.location.line == 4
    assert any("instance.computer(action=click_mouse)" in item for item in finding.evidence)

    assert graph.adg is not None
    node = next(
        n
        for n in graph.adg.nodes
        if n.kind == "tool" and n.attributes.get("tool_name") == "take_computer_action"
    )
    assert node.attributes["computer_control_actions"] == ["click_mouse"]
    assert node.attributes["computer_control_mutating"] is True


def test_langgraph_custom_computer_type_is_state_changing(tmp_path: Path) -> None:
    _write_langgraph_computer_action(tmp_path, "type_text")

    graph, findings = scan(tmp_path)
    tool = next(t for a in graph.agents for t in a.tools if t.name == "take_computer_action")

    assert {"computer.control", "external.write"} <= tool.capabilities
    assert tool.metadata["computer_control_actions"] == ["type_text"]
    assert any(f.rule_id == "AGT023" for f in findings)


def test_langgraph_custom_computer_screenshot_is_read_only(tmp_path: Path) -> None:
    _write_langgraph_computer_action(tmp_path, "take_screenshot")

    graph, findings = scan(tmp_path)
    tool = next(t for a in graph.agents for t in a.tools if t.name == "take_computer_action")

    assert {"computer.control", "data.read"} <= tool.capabilities
    assert "external.write" not in tool.capabilities
    assert tool.metadata["computer_control_actions"] == ["take_screenshot"]
    assert tool.metadata["computer_control_mutating"] is False
    assert tool.metadata["computer_control_readonly"] is True
    assert not any(f.rule_id == "AGT023" for f in findings)


def test_langgraph_unknown_literal_computer_action_is_not_assumed_mutating(tmp_path: Path) -> None:
    _write_langgraph_computer_action(tmp_path, "inspect_status")

    graph, findings = scan(tmp_path)
    tool = next(t for a in graph.agents for t in a.tools if t.name == "take_computer_action")

    assert "computer.control" in tool.capabilities
    assert "external.write" not in tool.capabilities
    assert tool.metadata["computer_control_actions"] == ["inspect_status"]
    assert tool.metadata["computer_control_mutating"] is False
    assert not any(f.rule_id == "AGT023" for f in findings)


def test_langgraph_computer_word_alone_does_not_infer_control(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """from langgraph.graph import StateGraph

def computer_status(state):
    return {"computer": state.get("computer")}

workflow = StateGraph(dict)
workflow.add_node("computer_status", computer_status)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(t for a in graph.agents for t in a.tools if t.name == "computer_status")

    assert "computer.control" not in tool.capabilities
    assert not any(f.rule_id == "AGT023" for f in findings)


def test_langgraph_page_click_is_high_confidence_computer_control(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """from langgraph.graph import StateGraph

def apply_browser_action(state):
    page.click(state["selector"])

workflow = StateGraph(dict)
workflow.add_node("apply_browser_action", apply_browser_action)
""",
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    tool = next(t for a in graph.agents for t in a.tools if t.name == "apply_browser_action")

    assert {"computer.control", "external.write"} <= tool.capabilities
    assert tool.metadata["computer_control_actions"] == ["click"]
    assert any(f.rule_id == "AGT023" for f in findings)
