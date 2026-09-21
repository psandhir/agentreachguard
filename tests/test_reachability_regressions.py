from itertools import permutations
from pathlib import Path

import pytest

from horustrace.analysis import build_attack_paths
from horustrace.models import Agent, AgentPolicy, Graph, InputSource, Tool
from horustrace.rules.builtin import evaluate
from horustrace.scanner import _propagate_adk_delegation, scan


@pytest.mark.parametrize("order", list(permutations(range(3))))
def test_transitive_authority_is_independent_of_agent_order(order):
    agents = [
        Agent(name="root", metadata={"delegates_to": ["middle"]},
              inputs=[InputSource(name="web", trust="untrusted")],
              policy=AgentPolicy(denied_capabilities={"process.execute"})),
        Agent(name="middle", metadata={"delegates_to": ["leaf"]}),
        Agent(name="leaf", tools=[Tool(
            name="shell", kind="shell", capabilities={"process.execute"},
        )]),
    ]
    graph = Graph(agents=[agents[i] for i in order])
    _propagate_adk_delegation(graph)
    assert "process.execute" in agents[0].capabilities
    graph.attack_paths = build_attack_paths(graph)
    root_ids = {f.rule_id for f in evaluate(graph) if f.agent == "root"}
    assert {"CAP002", "PATH001"} <= root_ids


def test_cyclic_delegation_terminates_without_duplicate_tools():
    a = Agent(name="a", metadata={"delegates_to": ["b", "b"]})
    b = Agent(name="b", metadata={"delegates_to": ["a", "leaf"]})
    leaf = Agent(name="leaf", tools=[Tool(
        name="shell", kind="shell", capabilities={"process.execute"},
    )])
    _propagate_adk_delegation(Graph(agents=[a, b, leaf]))
    assert "process.execute" in a.capabilities
    assert len(a.tools) == 1
    assert len(b.tools) == 2


@pytest.mark.parametrize("approval", [False, True])
@pytest.mark.parametrize("delegated", [False, True])
def test_classified_resources_reach_exfiltration_checks(tmp_path: Path, approval, delegated):
    (tmp_path / "horustrace.manifest.yaml").write_text(f"""
agents:
  - name: reader
    tools:
      - name: read_records
        capabilities: [data.read]
        resources:
          - selector: /finance/records
            classification: confidential
            access: [data.read]
      - name: upload
        capabilities: [external.write, network.external]
        approval: {str(approval).lower()}
        destinations: ['*']
""", encoding="utf-8")
    if delegated:
        (tmp_path / "agent.py").write_text('''
from google.adk import Agent
root_agent = Agent(name="root", sub_agents=[middle])
middle = Agent(name="middle", sub_agents=[reader])
reader = Agent(name="reader")
''', encoding="utf-8")
    graph, findings = scan(tmp_path)
    reader_ids = {f.rule_id for f in findings if f.agent == "reader"}
    assert "DATA003" in reader_ids
    assert ("AGT010" in reader_ids) is not approval
    assert ("PATH003" in reader_ids) is not approval
    if delegated:
        root = next(a for a in graph.agents if a.name == "root")
        assert root.sensitive_data_sources[0].selector == "/finance/records"
        assert root.effective_destinations[0].target == "*"
        root_ids = {f.rule_id for f in findings if f.agent == "root"}
        assert "DATA003" in root_ids
        assert ("AGT010" in root_ids) is not approval
        assert ("PATH003" in root_ids) is not approval


def test_write_only_sensitive_resource_does_not_imply_data_read():
    from horustrace.models import ResourceScope

    agent = Agent(name="writer", inputs=[InputSource(name="web", trust="untrusted")], tools=[
        Tool(name="write", kind="generic", capabilities={"data.write"}, resources=[
            ResourceScope(kind="file", selector="/secret", classification="confidential",
                          access={"data.write"}),
        ]),
    ])
    assert agent.sensitive_data_sources == []
