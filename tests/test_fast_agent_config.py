from pathlib import Path

from horustrace.scanner import scan


def test_fast_agent_yaml_server_binds_to_agent_reference(tmp_path: Path) -> None:
    (tmp_path / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    filesystem:
      target: "npx -y @modelcontextprotocol/server-filesystem ."
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("App")

@fast.agent(name="worker", servers=["filesystem"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "worker")

    assert len(agent.mcp_servers) == 1
    server = agent.mcp_servers[0]
    assert server.name == "filesystem"
    assert server.transport == "stdio"
    assert server.command == "npx"
    assert server.args == [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        ".",
    ]
    assert server.metadata["source"] == "fast_agent_yaml"
    assert server.metadata["binding_origin"] == "fast_agent_servers_reference"
    assert server.metadata["effective_agent"] == "worker"
    assert graph.unbound_mcp_servers == []


def test_fast_agent_yaml_remote_auth_evidence_is_preserved(tmp_path: Path) -> None:
    (tmp_path / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    remote:
      target: "https://mcp.example.test/mcp"
      headers:
        Authorization: "Bearer ${MCP_TOKEN}"
""",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("App")

@fast.agent(name="worker", servers=["remote"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    server = next(
        item
        for item in graph.agents[0].mcp_servers
        if item.name == "remote"
    )

    assert server.url == "https://mcp.example.test/mcp"
    assert server.authenticated is True
    assert server.metadata["credential_source"] == "env:MCP_TOKEN"
    assert server.identity == "worker:remote:mcp-auth"


def test_fast_agent_binding_uses_nearest_config_scope(tmp_path: Path) -> None:
    (tmp_path / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    shared:
      target: "https://parent.example.test/mcp"
""",
        encoding="utf-8",
    )
    child = tmp_path / "examples" / "demo"
    child.mkdir(parents=True)
    (child / "fast-agent.yaml").write_text(
        """
mcp:
  servers:
    shared:
      target: "https://child.example.test/mcp"
""",
        encoding="utf-8",
    )
    (child / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("Scoped")

@fast.agent(name="worker", servers=["shared"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "worker")

    assert [server.url for server in agent.mcp_servers] == [
        "https://child.example.test/mcp"
    ]
    assert len(graph.unbound_mcp_servers) == 1
    assert graph.unbound_mcp_servers[0].url == "https://parent.example.test/mcp"


def test_fast_agent_duplicate_same_scope_remains_ambiguous(tmp_path: Path) -> None:
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    for directory, url in (
        (first, "https://one.example.test/mcp"),
        (second, "https://two.example.test/mcp"),
    ):
        (directory / "mcp.json").write_text(
            '{"mcpServers":{"shared":{"url":"' + url + '"}}}',
            encoding="utf-8",
        )
    (tmp_path / "agent.py").write_text(
        """
from fast_agent import FastAgent

fast = FastAgent("App")

@fast.agent(name="worker", servers=["shared"])
async def main():
    pass
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert graph.agents[0].mcp_servers == []
    assert len(graph.unbound_mcp_servers) == 2
    assert {
        server.metadata.get("context_binding")
        for server in graph.unbound_mcp_servers
    } == {"ambiguous_fast_agent_reference"}
