from pathlib import Path

from agentreachguard.scanner import scan


def test_source_authority_cannot_be_hidden_by_manifest_budget(tmp_path: Path):
    (tmp_path / 'agent.py').write_text('''
from agents import Agent, ShellTool
shell = ShellTool(needs_approval=False)
agent = Agent(name="ops", tools=[shell])
''')
    (tmp_path / 'agentreachguard.manifest.yaml').write_text('''
version: 1
agents:
  - name: ops
    tools:
      - name: shell
        capabilities: [data.read]
        approval: true
    policy:
      denied_capabilities: [process.execute]
      require_approval_for: [process.execute]
''')
    graph, findings = scan(tmp_path)
    assert len(graph.agents) == 1
    assert graph.agents[0].tools[0].approval is False
    assert {'CAP002', 'CAP006', 'AGT020'} <= {f.rule_id for f in findings}


def test_terraform_enriches_manifest_identity_reference(tmp_path: Path):
    (tmp_path / 'agentreachguard.manifest.yaml').write_text('''
agents:
  - name: ops
    identities: [serviceAccount:ops@example.test]
''')
    (tmp_path / 'iam.tf').write_text('''resource "google_project_iam_member" "ops" {
  project = "production"
  role = "roles/owner"
  member = "serviceAccount:ops@example.test"
}
''')
    graph, findings = scan(tmp_path)
    identity = graph.agents[0].identities[0]
    assert identity.provider == 'gcp'
    assert identity.roles == {'roles/owner'}
    assert any(f.rule_id == 'IDN001' and f.agent == 'ops' for f in findings)


def test_shared_tool_is_evaluated_against_each_agents_policy(tmp_path: Path):
    (tmp_path / 'agent.py').write_text('''
from agents import Agent, ShellTool
shared = ShellTool(needs_approval=True)
a = Agent(name="a", tools=[shared])
b = Agent(name="b", tools=[shared])
''')
    (tmp_path / 'agentreachguard.manifest.yaml').write_text('''
agents:
  - name: a
    policy:
      denied_capabilities: [process.execute]
  - name: b
    policy:
      require_approval_for: [process.execute]
''')
    _, findings = scan(tmp_path)
    assert any(f.rule_id == 'CAP002' and f.agent == 'a' for f in findings)
    assert not any(f.rule_id in {'CAP002', 'CAP006'} and f.agent == 'b' for f in findings)


def test_cross_file_delegation_carries_classified_resources(tmp_path: Path):
    (tmp_path / 'root_agent.yaml').write_text('''
name: root
sub_agents:
  - config_path: middle.yaml
''')
    (tmp_path / 'middle.yaml').write_text('''
name: middle_runtime
sub_agents:
  - config_path: reader.yaml
''')
    (tmp_path / 'reader.yaml').write_text('''
name: reader_runtime
model: model
''')
    (tmp_path / 'agentreachguard.manifest.yaml').write_text('''
agents:
  - name: reader_runtime
    data:
      - name: records
        selector: /finance/records
        classification: confidential
  - name: root
    tools:
      - name: upload
        capabilities: [external.write]
        destinations: ['*']
''')
    graph, findings = scan(tmp_path)
    root = next(a for a in graph.agents if a.name == 'root')
    assert root.sensitive_data_sources[0].selector == '/finance/records'
    assert not graph.coverage.incomplete
    assert {'AGT010', 'DATA003', 'PATH003'} <= {
        f.rule_id for f in findings if f.agent == 'root'
    }


def test_manifest_tool_overlay_is_isolated_between_shared_agents(tmp_path: Path):
    (tmp_path / 'agent.py').write_text("""
from agents import Agent, ShellTool
shared = ShellTool(needs_approval=True)
a = Agent(name="a", tools=[shared])
b = Agent(name="b", tools=[shared])
""")
    (tmp_path / 'agentreachguard.manifest.yaml').write_text("""
agents:
  - name: a
    tools:
      - name: shared
        approval: false
""")
    graph, findings = scan(tmp_path)
    approvals = {a.name: a.tools[0].approval for a in graph.agents}
    assert approvals == {'a': False, 'b': True}
    assert any(f.rule_id == 'AGT020' and f.agent == 'a' for f in findings)
    assert not any(f.rule_id == 'AGT020' and f.agent == 'b' for f in findings)
