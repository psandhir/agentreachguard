from pathlib import Path

from horustrace.models import AgentReachability, FlowExecutionContext
from horustrace.scanner import scan


def _shared_auth_project(root: Path) -> None:
    core = root / "core"
    cli = root / "cli"
    server = root / "mcp_server"
    core.mkdir()
    cli.mkdir()
    server.mkdir()

    (core / "auth_tokens.py").write_text(
        """import httpx

def fetch_cli_config():
    return httpx.get("https://coordinator.example/auth/config")

def refresh_access_token(cli_config):
    return httpx.post(
        "https://coordinator.example/oauth/token",
        data={"client_id": cli_config},
    )

def get_valid_access_token():
    cli_config = fetch_cli_config()
    return refresh_access_token(cli_config)
""",
        encoding="utf-8",
    )
    (cli / "utils.py").write_text(
        """from core.auth_tokens import get_valid_access_token

def login():
    return get_valid_access_token()
""",
        encoding="utf-8",
    )
    (server / "server.py").write_text(
        """from core.auth_tokens import get_valid_access_token

class MCPServer:
    def __init__(self):
        self.access_token = get_valid_access_token()
""",
        encoding="utf-8",
    )


def test_shared_runtime_flow_records_cli_and_mcp_server_entrypoints(tmp_path: Path) -> None:
    _shared_auth_project(tmp_path)

    graph, _ = scan(tmp_path)
    flow = next(
        item
        for item in graph.flow_paths
        if item.execution_context is FlowExecutionContext.RUNTIME
        and item.source_kind == "external_http_response"
        and item.sink_kind == "external_send"
    )

    assert flow.agent_reachability is AgentReachability.UNKNOWN
    assert flow.metadata["agent_reachability_basis"] == "no_agent_tool_binding_evidence"
    assert flow.metadata["inbound_entrypoint_kinds"] == ["cli", "mcp_server_lifecycle"]

    entrypoints = {
        item["kind"]: item
        for item in flow.metadata["inbound_entrypoints"]
    }
    assert entrypoints["cli"]["function"] == "cli.utils.login"
    assert entrypoints["cli"]["inbound_call_chain"] == [
        "cli.utils.login",
        "core.auth_tokens.get_valid_access_token",
    ]
    assert (
        entrypoints["mcp_server_lifecycle"]["function"]
        == "mcp_server.server.MCPServer.__init__"
    )
    assert entrypoints["mcp_server_lifecycle"]["inbound_call_chain"] == [
        "mcp_server.server.MCPServer.__init__",
        "core.auth_tokens.get_valid_access_token",
    ]
    assert flow.metadata["inbound_provenance_truncated"] is False


def test_inbound_provenance_does_not_upgrade_runtime_reachability(tmp_path: Path) -> None:
    _shared_auth_project(tmp_path)

    graph, _ = scan(tmp_path)
    runtime_flows = [
        item
        for item in graph.flow_paths
        if item.execution_context is FlowExecutionContext.RUNTIME
    ]

    assert runtime_flows
    assert all(
        item.agent_reachability is AgentReachability.UNKNOWN
        for item in runtime_flows
    )



def test_entrypoint_budget_preserves_distinct_runtime_kinds(tmp_path: Path) -> None:
    _shared_auth_project(tmp_path)

    server = tmp_path / "mcp_server" / "server.py"
    server.write_text(
        """from core.auth_tokens import get_valid_access_token

class MCPServer:
    def __init__(self):
        self._init_arcade_client()

    def _init_arcade_client(self):
        return self._load_config_values()

    def _load_config_values(self):
        return get_valid_access_token()
""",
        encoding="utf-8",
    )

    tests = tmp_path / "tests"
    tests.mkdir()
    functions = "\n\n".join(
        f"def test_entry_{index}():\n    return get_valid_access_token()"
        for index in range(48)
    )
    (tests / "test_many_entrypoints.py").write_text(
        "from core.auth_tokens import get_valid_access_token\n\n" + functions + "\n",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    flow = next(
        item
        for item in graph.flow_paths
        if item.execution_context is FlowExecutionContext.RUNTIME
        and item.source_kind == "external_http_response"
        and item.sink_kind == "external_send"
    )

    assert flow.agent_reachability is AgentReachability.UNKNOWN
    assert flow.metadata["inbound_entrypoint_candidates"] > 32
    assert len(flow.metadata["inbound_entrypoints"]) == 32
    assert flow.metadata["inbound_provenance_truncated"] is True
    assert "test" in flow.metadata["inbound_entrypoint_kinds"]
    assert "mcp_server_lifecycle" in flow.metadata["inbound_entrypoint_kinds"]
    assert any(
        item["function"] == "mcp_server.server.MCPServer.__init__"
        for item in flow.metadata["inbound_entrypoints"]
    )



def test_proven_non_agent_flows_skip_reverse_provenance(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "maintenance.py").write_text(
        """import httpx

def sync():
    response = httpx.get("https://source.example/data")
    return httpx.post("https://sink.example/data", data=response)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    flow = next(iter(graph.flow_paths))

    assert flow.agent_reachability is AgentReachability.PROVEN_NON_AGENT
    assert "inbound_entrypoints" not in flow.metadata
    assert "inbound_entrypoint_candidates" not in flow.metadata
