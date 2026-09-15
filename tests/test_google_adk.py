from pathlib import Path

from agentreachguard.scanner import scan


def write(tmp_path: Path, text: str, name: str = "agent.py") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_adk_function_tool_confirmation(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools import FunctionTool

def delete_customer(customer_id: str):
    pass

root_agent = Agent(name="ops", model="gemini-flash-latest", tools=[
    FunctionTool(delete_customer, require_confirmation=True)
])
''')
    graph, findings = scan(tmp_path)
    assert len(graph.agents) == 1
    assert graph.agents[0].metadata["framework"] == "google-adk"
    assert not any(f.rule_id == "AGT021" for f in findings)


def test_adk_unsafe_local_code_executor(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.code_executors import UnsafeLocalCodeExecutor
root_agent = Agent(name="coder", model="gemini-flash-latest", code_executor=UnsafeLocalCodeExecutor())
''')
    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "ADK002" in ids
    assert "PATH001" in ids


def test_adk_environment_local_detected(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.environment import LocalEnvironment
from google.adk.tools.environment import EnvironmentToolset
local = LocalEnvironment(working_dir="/")
env_tools = EnvironmentToolset(environment=local)
root_agent = Agent(name="coder", model="gemini-flash-latest", tools=[env_tools])
''')
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "ADK003" for f in findings)


def test_adk_bash_policy_missing(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.bash_tool import ExecuteBashTool
bash = ExecuteBashTool()
root_agent = Agent(name="ops", model="gemini-flash-latest", tools=[bash])
''')
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "ADK004" for f in findings)


def test_adk_mcp_remote_auth_filter_confirmation(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
mcp = McpToolset(
  connection_params=StreamableHTTPConnectionParams(
    url="https://mcp.example.com/mcp",
    headers={"Authorization": "Bearer dynamic"},
  ),
  tool_filter=["read_ticket"],
  require_confirmation=True,
)
root_agent = Agent(name="support", model="gemini-flash-latest", tools=[mcp])
''')
    graph, findings = scan(tmp_path)
    assert graph.agents[0].mcp_servers[0].authenticated is True
    ids = {f.rule_id for f in findings}
    assert "AGT030" not in ids
    assert "AGT032" not in ids


def test_adk_bigquery_blocked_write_removes_data_write(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.bigquery import BigQueryToolset
from google.adk.tools.bigquery.config import BigQueryToolConfig, WriteMode
cfg = BigQueryToolConfig(write_mode=WriteMode.BLOCKED)
bq = BigQueryToolset(bigquery_tool_config=cfg)
root_agent = Agent(name="analyst", model="gemini-flash-latest", tools=[bq])
''')
    graph, findings = scan(tmp_path)
    assert "data.write" not in graph.agents[0].capabilities
    assert not any(f.rule_id == "ADK006" for f in findings)


def test_adk_computer_use_detected(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.computer_use.computer_use_toolset import ComputerUseToolset
computer = ComputerUseToolset(computer=PlaywrightComputer())
root_agent = Agent(name="browser", model="gemini-computer-use", tools=[computer])
''')
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "ADK005" for f in findings)


def test_adk_subagent_delegation_propagates_privilege(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.bash_tool import ExecuteBashTool
child = Agent(name="privileged_child", model="gemini-flash-latest", tools=[ExecuteBashTool()])
root_agent = Agent(name="coordinator", model="gemini-flash-latest", sub_agents=[child])
''')
    graph, findings = scan(tmp_path)
    parent = next(a for a in graph.agents if a.name == "coordinator")
    assert "process.execute" in parent.capabilities
    assert any(f.rule_id == "PATH001" and f.agent == "coordinator" for f in findings)


def test_adk_remote_a2a_http_unauthenticated(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
remote = RemoteA2aAgent(name="remote", agent_card="http://remote.example/.well-known/agent-card.json")
''')
    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "ADK009" in ids
    assert "ADK010" in ids


def test_adk_yaml_config(tmp_path: Path) -> None:
    write(tmp_path, '''
name: search_agent
model: gemini-flash-latest
instruction: Search the web.
tools:
  - name: GoogleSearchTool
''', "root_agent.yaml")
    graph, _ = scan(tmp_path)
    assert len(graph.agents) == 1
    assert graph.agents[0].metadata["adk_config"] is True
    assert "network.external" in graph.agents[0].capabilities


def test_adk_env_secret_redacted_finding(tmp_path: Path) -> None:
    write(tmp_path, 'GOOGLE_API_KEY="test-placeholder-not-a-real-key"\n', ".env")
    _, findings = scan(tmp_path)
    finding = next(f for f in findings if f.rule_id == "IDN004")
    assert "test-placeholder-not-a-real-key" not in " ".join(finding.evidence)


def test_adk_google_api_toolset_broad_oauth_scope_reaches_identity_layer(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.google_api_tool import GoogleApiToolset
api = GoogleApiToolset(
    additional_scopes=["https://www.googleapis.com/auth/cloud-platform"],
    client_secret="test-placeholder-not-a-real-secret",
)
root_agent = Agent(name="api_agent", model="gemini-flash-latest", tools=[api])
''')
    graph, findings = scan(tmp_path)
    assert any(i.oauth_scopes == {"https://www.googleapis.com/auth/cloud-platform"} for i in graph.identities)
    ids = {f.rule_id for f in findings}
    assert "IDN003" in ids
    assert "IDN004" in ids
    assert not any("test-placeholder-not-a-real-secret" in " ".join(f.evidence) for f in findings)


def test_adk_before_tool_callback_counts_as_agent_safety_control(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.bash_tool import ExecuteBashTool

def security_gate(tool, args, context):
    return None

root_agent = Agent(
    name="controlled_ops",
    model="gemini-flash-latest",
    tools=[ExecuteBashTool()],
    before_tool_callback=security_gate,
)
''')
    _, findings = scan(tmp_path)
    assert not any(f.rule_id == "ADK001" for f in findings)


def test_adk_agenttool_plugin_isolation_detected(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk import Agent
from google.adk.tools.agent_tool import AgentTool
child = Agent(name="child", model="gemini-flash-latest")
delegate = AgentTool(agent=child, include_plugins=False)
root_agent = Agent(name="parent", model="gemini-flash-latest", tools=[delegate])
''')
    _, findings = scan(tmp_path)
    assert any(f.rule_id == "ADK008" for f in findings)


def test_adk_secure_remote_a2a_does_not_emit_transport_auth_findings(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
remote = RemoteA2aAgent(
    name="remote",
    agent_card="https://remote.example/.well-known/agent-card.json",
    auth_scheme=object(),
    auth_credential=object(),
)
''')
    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "ADK009" not in ids
    assert "ADK010" not in ids


def test_adk_yaml_cross_file_subagent_privilege_propagates(tmp_path: Path) -> None:
    child_dir = tmp_path / "privileged_worker"
    child_dir.mkdir()
    (child_dir / "agent.yaml").write_text('''
name: shell_specialist
model: gemini-flash-latest
code_executor:
  name: UnsafeLocalCodeExecutor
''', encoding="utf-8")
    (tmp_path / "root_agent.yaml").write_text('''
name: coordinator
model: gemini-flash-latest
sub_agents:
  - config_path: privileged_worker/agent.yaml
''', encoding="utf-8")
    graph, findings = scan(tmp_path)
    parent = next(a for a in graph.agents if a.name == "coordinator")
    assert "process.execute" in parent.capabilities
    assert any(f.rule_id == "PATH001" and f.agent == "coordinator" for f in findings)


def test_adk_workflow_agent_is_first_class(tmp_path: Path) -> None:
    write(tmp_path, '''
from google.adk.agents import Agent, ParallelAgent
research = Agent(name="research", model="gemini-flash-latest")
review = Agent(name="review", model="gemini-flash-latest")
root_agent = ParallelAgent(name="workflow", sub_agents=[research, review])
''')
    graph, _ = scan(tmp_path)
    workflow = next(a for a in graph.agents if a.name == "workflow")
    assert workflow.metadata.get("workflow") == "ParallelAgent"
    assert set(workflow.metadata.get("delegates_to") or []) == {"research", "review"}
