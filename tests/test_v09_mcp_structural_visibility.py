from pathlib import Path

from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def test_programmatic_mcp_entities_are_visible_without_agent_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.py").write_text(
        """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs")

@mcp.tool()
def search_docs(query: str) -> str:
    return query
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert graph.agents == []
    assert [tool.name for tool in graph.unbound_tools] == ["search_docs"]
    assert any(server.name == "docs" for server in graph.unbound_mcp_servers)

    assert graph.adg is not None
    tool_node = next(
        node
        for node in graph.adg.nodes
        if node.kind == "tool" and node.name == "search_docs"
    )
    server_node = next(
        node
        for node in graph.adg.nodes
        if node.kind == "mcp_server" and node.name == "docs"
    )
    assert tool_node.attributes["unbound"] is True
    assert server_node.attributes["unbound"] is True
    assert tool_node.attributes["binding_state"] == "unbound"
    assert server_node.attributes["binding_state"] == "unbound"
    assert not any(
        edge.kind == "INVOKES"
        and edge.target in {tool_node.node_id, server_node.node_id}
        for edge in graph.adg.edges
    )
    assert effective_authority_report(graph)["relationships"] == []


def test_configured_mcp_server_is_structurally_visible_but_unbound(
    tmp_path: Path,
) -> None:
    (tmp_path / "mcp.json").write_text(
        """
{
  "mcpServers": {
    "github": {
      "url": "https://mcp.example.test/github",
      "allowedTools": ["issues_read"]
    }
  }
}
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert graph.agents == []
    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "mcp_server" and item.name == "github"
    )
    assert node.attributes["unbound"] is True
    assert node.attributes["transport"] == "http"
    assert node.attributes["allowed_tools"] == ["issues_read"]
    assert not any(
        edge.kind == "INVOKES" and edge.target == node.node_id
        for edge in graph.adg.edges
    )
    assert effective_authority_report(graph)["relationships"] == []


def test_stdio_mcp_client_definition_is_visible_without_fabricated_binding(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.py").write_text(
        """
from mcp import StdioServerParameters

params = StdioServerParameters(
    command="python",
    args=["server.py"],
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert graph.agents == []
    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "mcp_server" and item.name == "params"
    )
    assert node.attributes["unbound"] is True
    assert node.attributes["transport"] == "stdio"
    assert not any(edge.kind == "INVOKES" for edge in graph.adg.edges)
