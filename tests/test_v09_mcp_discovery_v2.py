from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def test_custom_mcp_connection_wrapper_is_structurally_visible(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.py").write_text(
        """
from mcp import ClientSession, StdioServerParameters

class MCPServerConnection:
    def __init__(self, command: str):
        self.command = command
        self.session = None

    async def connect(self):
        params = StdioServerParameters(command=self.command, args=[])
        self.session = ClientSession(read_stream, write_stream)

server = MCPServerConnection("python")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert graph.agents == []
    server = next(item for item in graph.unbound_mcp_servers if item.name == "server")
    assert server.transport == "stdio"
    assert server.metadata["wrapper_class"] == "MCPServerConnection"
    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "mcp_server" and item.name == "server"
    )
    assert node.attributes["unbound"] is True
    assert not any(edge.kind == "INVOKES" and edge.target == node.node_id for edge in graph.adg.edges)
    assert effective_authority_report(graph)["relationships"] == []


def test_custom_mcp_server_wrapper_requires_strong_mcp_internals(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.py").write_text(
        """
from mcp.server import Server

class AWSMCPServer:
    def __init__(self):
        self.server = Server("aws-cli-server")

server = AWSMCPServer()
""",
        encoding="utf-8",
    )
    (tmp_path / "config.py").write_text(
        """
from mcp import ClientSession

class MCPServerConfig:
    def __init__(self, name):
        self.name = name

config = MCPServerConfig("docs")
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    names = {server.name for server in graph.unbound_mcp_servers}
    assert "server" in names
    assert "config" not in names


def test_openai_mcp_definition_is_visible_without_agent_binding(
    tmp_path: Path,
) -> None:
    (tmp_path / "care.py").write_text(
        """
from agents.mcp.server import MCPServerSse

care_mcp = MCPServerSse(
    name="KnoliaCare",
    params={"url": "http://localhost:8002/sse"},
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert graph.agents == []
    server = next(item for item in graph.unbound_mcp_servers if item.name == "care_mcp")
    assert server.transport == "sse"
    assert server.url == "http://localhost:8002/sse"
    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "mcp_server" and item.name == "care_mcp"
    )
    assert node.attributes["unbound"] is True
    assert not any(edge.kind == "INVOKES" and edge.target == node.node_id for edge in graph.adg.edges)


def test_pydantic_legacy_mcp_servers_binding_is_normalized(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

mcp_server = MCPServerStdio("python", ["mcp_server.py"], env={})
agent = Agent("openai:gpt-5", mcp_servers=[mcp_server])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    server = next(item for item in agent.mcp_servers if item.name == "mcp_server")
    assert server.transport == "stdio"
    assert server.command == "python"
    assert server.args == ["mcp_server.py"]


def test_pydantic_mcp_server_stdio_works_in_toolsets(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

server = MCPServerStdio(
    "uvx",
    args=["mcp-run-python@latest", "stdio"],
    timeout=10,
)
agent = Agent(
    "openai:gpt-5",
    toolsets=[server],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    agent = next(item for item in graph.agents if item.name == "agent")
    server = next(item for item in agent.mcp_servers if item.name == "server")
    assert server.transport == "stdio"
    assert server.command == "uvx"
    assert server.args == ["mcp-run-python@latest", "stdio"]


def test_pydantic_aliased_mcp_server_stdio_is_normalized(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from pydantic_ai import Agent as PyAIAgent
from pydantic_ai.mcp import MCPServerStdio as PyAIMCPServerStdio

tavily_mcp_server = PyAIMCPServerStdio(
    command="npx",
    args=["-y", "tavily-mcp@0.1.4"],
)
researcher_agent = PyAIAgent(
    "openai:gpt-5",
    mcp_servers=[tavily_mcp_server],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    # The legacy aliased Agent constructor is not normalized here; the MCP
    # declaration must still be preserved structurally rather than lost.
    server = next(
        item
        for item in graph.unbound_mcp_servers
        if item.name == "tavily_mcp_server"
    )
    assert server.transport == "stdio"
    assert server.command == "npx"
    assert server.args == ["-y", "tavily-mcp@0.1.4"]
    assert server.metadata["constructor_alias"] == "PyAIMCPServerStdio"
    assert server.metadata["binding_state"] == "unbound"
    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "mcp_server" and item.name == "tavily_mcp_server"
    )
    assert node.attributes["unbound"] is True
