from pathlib import Path

from horustrace.adapters.registry import detect_python_frameworks
from horustrace.scanner import scan


def test_langgraph_class_attribute_graph_is_normalized(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(
        """
from langgraph.graph import StateGraph

class Workflow:
    def build(self):
        self.workflow = StateGraph(dict)
        self.workflow.add_node("research", self.research)
        self.workflow.add_node("write", self.write)
        self.workflow.add_edge("research", "write")

    def research(self, state):
        return state

    def write(self, state):
        return state
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(agent for agent in graph.agents if agent.metadata.get("framework") == "langgraph")
    assert agent.name == "self.workflow"
    assert {tool.name for tool in agent.tools} == {"research", "write"}
    assert ("research", "write") in agent.metadata["control_edges"]


def test_langgraph_function_local_graph_is_normalized(tmp_path: Path) -> None:
    (tmp_path / "factory.py").write_text(
        """
from langgraph.graph import StateGraph

def build_graph():
    builder = StateGraph(dict)
    builder.add_node("fetch", fetch)
    return builder.compile()

def fetch(state):
    return state
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(agent for agent in graph.agents if agent.name == "builder")
    assert [tool.name for tool in agent.tools] == ["fetch"]


def test_langgraph_create_react_agent_is_normalized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from langgraph.prebuilt import create_react_agent

def search_web(query):
    return query

tools = [search_web]
agent = create_react_agent("openai:gpt-4o", tools=tools)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(agent for agent in graph.agents if agent.name == "agent")
    assert agent.metadata["agent_type"] == "create_react_agent"
    assert [tool.name for tool in agent.tools] == ["search_web"]


def test_programmatic_mcp_stdio_client_is_discovered(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        """
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

params = StdioServerParameters(command="python", args=["server.py"])

async def run():
    async with stdio_client(params) as streams:
        pass
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    servers = graph.all_mcp_servers()
    assert len(servers) == 1
    assert servers[0].transport == "stdio"
    assert servers[0].command == "python"
    assert servers[0].args == ["server.py"]


def test_fastmcp_server_and_tools_are_discovered(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        """
from fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool
def search(query: str):
    return query

if __name__ == "__main__":
    mcp.run(transport="sse")
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(server.name == "demo" and server.transport == "sse"
               for server in graph.all_mcp_servers())
    assert any(tool.name == "search" and tool.kind == "mcp_exposed_tool"
               for tool in graph.all_tools())


def test_langgraph_and_mcp_adapters_compose(tmp_path: Path) -> None:
    path = tmp_path / "mixed.py"
    path.write_text(
        """
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient({
    "weather": {"transport": "stdio", "command": "python", "args": ["weather.py"]}
})
agent = create_react_agent("openai:gpt-4o", tools=[])
""",
        encoding="utf-8",
    )
    assert detect_python_frameworks(path) == ["langgraph", "mcp-python"]
    graph, _ = scan(tmp_path)
    assert any(agent.metadata.get("framework") == "langgraph" for agent in graph.agents)
    assert any(server.name == "weather" for server in graph.all_mcp_servers())


def test_framework_detected_but_not_normalized_is_incomplete(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """
from langgraph.graph import StateGraph

def unrelated():
    return "no graph constructed"
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    diagnostic = next(
        item for item in graph.coverage.diagnostics
        if item.kind == "framework_not_normalized"
    )
    assert diagnostic.diagnostic_id == "ARG-COV-015"
    assert diagnostic.details["framework"] == "langgraph"


def test_notebook_code_cells_are_scanned_statically(tmp_path: Path) -> None:
    (tmp_path / "agent.ipynb").write_text(
        """{
  "cells": [
    {
      "cell_type": "code",
      "metadata": {},
      "source": [
        "from langgraph.prebuilt import create_react_agent\\n",
        "agent = create_react_agent('openai:gpt-4o', tools=[])\\n"
      ],
      "outputs": [],
      "execution_count": null
    }
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(agent for agent in graph.agents if agent.metadata.get("framework") == "langgraph")
    assert agent.location is not None
    assert agent.location.path.name == "agent.ipynb"


def test_parse_diagnostic_contains_reason_details(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    graph, _ = scan(tmp_path)
    diagnostic = next(item for item in graph.coverage.diagnostics if item.kind == "parse_error")
    assert diagnostic.details["exception_type"] == "SyntaxError"
    assert diagnostic.details["reason"]


def test_openai_generic_agent_and_static_mcp_url_are_normalized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
from agents.mcp import MCPServerStreamableHttp

URL = "https://mcp.example.test/mcp"
agent = Agent[dict](name="starter", tools=[])
server = MCPServerStreamableHttp(
    params={
        "url": URL,
        "headers": {"Authorization": f"Bearer {token}"},
    }
)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(agent.name == "starter" for agent in graph.agents)
    server = next(item for item in graph.all_mcp_servers() if item.name == "server")
    assert server.url == "https://mcp.example.test/mcp"
    assert server.authenticated is True


def test_langgraph_router_literal_returns_are_resolved(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(
        """
from typing import Literal
from langgraph.graph import StateGraph

def route(state) -> Literal["tools", "human"]:
    if state:
        return "tools"
    return "human"

builder = StateGraph(dict)
builder.add_node("start", lambda state: state)
builder.add_node("tools", lambda state: state)
builder.add_node("human", lambda state: state)
builder.add_conditional_edges("start", route)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(agent for agent in graph.agents if agent.name == "builder")
    assert ("start", "tools") in agent.metadata["control_edges"]
    assert ("start", "human") in agent.metadata["control_edges"]
    assert not any(item.kind == "unresolved_handoff" for item in graph.coverage.diagnostics)


def test_notebook_non_python_cells_do_not_create_parse_failure(tmp_path: Path) -> None:
    (tmp_path / "mixed.ipynb").write_text(
        """{
  "cells": [
    {"cell_type": "code", "metadata": {}, "source": ["%%html\\n", "<h1>hello</h1>\\n"]},
    {"cell_type": "code", "metadata": {}, "source": ["pip install example-package\\n"]},
    {"cell_type": "code", "metadata": {}, "source": [
      "from langgraph.prebuilt import create_react_agent\\n",
      "agent = create_react_agent('openai:gpt-4o', tools=[])\\n"
    ]}
  ],
  "metadata": {},
  "nbformat": 4,
  "nbformat_minor": 5
}""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(agent.metadata.get("framework") == "langgraph" for agent in graph.agents)
    assert not any(item.kind == "parse_error" for item in graph.coverage.diagnostics)
    skipped = [
        item for item in graph.coverage.diagnostics
        if item.kind == "notebook_non_python_cell"
    ]
    assert skipped
    assert all(item.incomplete is False for item in skipped)


def test_jinja_python_template_is_skipped_without_incomplete_parse_error(tmp_path: Path) -> None:
    (tmp_path / "template.py").write_text(
        """
from google.adk import Agent
{%- if cookiecutter.enabled %}
root_agent = Agent(name="root")
{%- endif %}
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert not any(item.kind == "parse_error" for item in graph.coverage.diagnostics)
    diagnostic = next(
        item for item in graph.coverage.diagnostics if item.kind == "templated_source"
    )
    assert diagnostic.incomplete is False


def test_context_managed_multiserver_mcp_client_is_discovered(tmp_path: Path) -> None:
    (tmp_path / "client.py").write_text(
        """
from langchain_mcp_adapters.client import MultiServerMCPClient

async def run():
    async with MultiServerMCPClient() as client:
        await client.connect_to_server(
            "slack",
            url="https://mcp.example.test/mcp",
        )
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    server = next(item for item in graph.all_mcp_servers() if item.name == "slack")
    assert server.transport == "streamable-http"
    assert server.url == "https://mcp.example.test/mcp"


def test_local_agents_package_does_not_trigger_openai_adapter(tmp_path: Path) -> None:
    path = tmp_path / "client.py"
    path.write_text(
        "from agents.mcp_agent import run_mcp_agent\n",
        encoding="utf-8",
    )
    assert "openai-agents" not in detect_python_frameworks(path)


def test_vertex_ai_rag_retrieval_is_recognized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from google.adk.agents import Agent
from google.adk.tools.retrieval.vertex_ai_rag_retrieval import VertexAiRagRetrieval

rag_tool = VertexAiRagRetrieval(
    name="retrieve_documents",
    description="retrieve",
    rag_resources=[],
)
root_agent = Agent(name="rag", tools=[rag_tool])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "rag")
    tool = next(item for item in agent.tools if item.name == "rag_tool")
    assert "data.read" in tool.capabilities
    assert "network.external" in tool.capabilities
    assert not any(item.kind == "unresolved_tool" for item in graph.coverage.diagnostics)


def test_temporal_activity_as_tool_is_recognized(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from datetime import timedelta
from agents import Agent
from temporalio.contrib import openai_agents as temporal_agents

def generate_pdf(value):
    return value

agent = Agent(
    name="pdf",
    tools=[
        temporal_agents.workflow.activity_as_tool(
            generate_pdf,
            start_to_close_timeout=timedelta(seconds=10),
        )
    ],
)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "pdf")
    assert any(tool.kind == "temporal_activity_tool" for tool in agent.tools)
    assert not any(item.kind == "unresolved_tool" for item in graph.coverage.diagnostics)


def test_openai_agent_as_tool_is_delegated_tool(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent

worker = Agent(name="worker")
worker_tool = worker.as_tool(tool_name="worker_tool")
lead = Agent(name="lead", tools=[worker_tool])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    lead = next(item for item in graph.agents if item.name == "lead")
    tool = next(item for item in lead.tools if item.name == "worker_tool")
    assert tool.kind == "delegated_agent"
    assert "agent.delegate" in tool.capabilities
    assert not any(item.kind == "unresolved_tool" for item in graph.coverage.diagnostics)


def test_imported_openai_tool_resolves_from_repository_evidence(tmp_path: Path) -> None:
    package = tmp_path / "app"
    tools_dir = package / "tools"
    tools_dir.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (tools_dir / "__init__.py").write_text(
        "from .emoji import add_emoji_reaction\n", encoding="utf-8"
    )
    (tools_dir / "emoji.py").write_text(
        """
from agents import function_tool

@function_tool
def add_emoji_reaction(value):
    return value
""",
        encoding="utf-8",
    )
    (package / "agent.py").write_text(
        """
from agents import Agent
from app.tools import add_emoji_reaction

agent = Agent(name="starter", tools=[add_emoji_reaction])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "starter")
    tool = next(item for item in agent.tools if item.name == "add_emoji_reaction")
    assert tool.metadata.get("repository_resolved") is True
    assert not any(
        item.kind in {"unresolved_tool", "external_helper_semantics_unresolved"}
        for item in graph.coverage.diagnostics
    )


def test_static_mcp_http_without_headers_is_unauthenticated(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient({
    "weather": {
        "url": "http://localhost:8000/mcp/",
        "transport": "streamable_http",
    }
})
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    server = next(item for item in graph.all_mcp_servers() if item.name == "weather")
    assert server.authenticated is False
    assert not any(
        item.kind == "authentication_unknown" for item in graph.coverage.diagnostics
    )


def test_python_runtime_command_is_resolved_for_mcp(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
import sys
from langchain_mcp_adapters.client import MultiServerMCPClient

python_path = sys.executable

async def main():
    async with MultiServerMCPClient() as client:
        await client.connect_to_server(
            "copywriter",
            command=python_path,
            args=["server.py"],
        )
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    server = next(item for item in graph.all_mcp_servers() if item.name == "copywriter")
    assert server.command == "<python-executable>"
    assert not any(
        item.kind == "dynamic_configuration" for item in graph.coverage.diagnostics
    )


def test_langgraph_tools_condition_is_finite_router(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(
        """
from langgraph.graph import StateGraph
from langgraph.prebuilt import tools_condition

builder = StateGraph(dict)
builder.add_node("call_model", lambda state: state)
builder.add_node("tools", lambda state: state)
builder.add_conditional_edges("call_model", tools_condition)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "builder")
    assert ("call_model", "tools") in agent.metadata["control_edges"]
    assert ("call_model", "__end__") in agent.metadata["control_edges"]
    assert not any(item.kind == "unresolved_handoff" for item in graph.coverage.diagnostics)


def test_langgraph_conditional_edges_list_path_map_is_resolved(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(
        """
from langgraph.graph import StateGraph

def route(state):
    return "alpha"

builder = StateGraph(dict)
builder.add_node("start", lambda state: state)
builder.add_node("alpha", lambda state: state)
builder.add_node("beta", lambda state: state)
builder.add_conditional_edges("start", route, ["alpha", "beta"])
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "builder")
    assert ("start", "alpha") in agent.metadata["control_edges"]
    assert ("start", "beta") in agent.metadata["control_edges"]
    assert not any(
        item.kind == "unresolved_handoff" for item in graph.coverage.diagnostics
    )


def test_external_named_mcp_reference_remains_incomplete(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent

agent = Agent(
    name="configured-mcp",
    mcp_servers=["fetch", "filesystem"],
)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert {server.name for server in graph.all_mcp_servers()} >= {"fetch", "filesystem"}
    assert any(
        item.kind == "dynamic_mcp_endpoint" for item in graph.coverage.diagnostics
    )


def test_output_heavy_notebook_can_exceed_normal_source_limit(tmp_path: Path) -> None:
    payload = "x" * (5 * 1024 * 1024 + 1024)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [payload],
            },
            {
                "cell_type": "code",
                "metadata": {},
                "source": [
                    "from langgraph.prebuilt import create_react_agent\n",
                    "agent = create_react_agent('openai:gpt-4o', tools=[])\n",
                ],
            },
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    import json

    (tmp_path / "large.ipynb").write_text(
        json.dumps(notebook),
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(agent.metadata.get("framework") == "langgraph" for agent in graph.agents)
    assert not any(
        item.kind == "unsupported_security_construct"
        for item in graph.coverage.diagnostics
    )


def test_bare_local_agents_import_without_sdk_symbols_is_not_openai(tmp_path: Path) -> None:
    path = tmp_path / "main.py"
    path.write_text(
        "from agents import judge_agent, mask_agent, sql_agent\n",
        encoding="utf-8",
    )
    assert "openai-agents" not in detect_python_frameworks(path)


def test_named_mcp_references_do_not_duplicate_unresolved_tool(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent

agent = Agent(
    name="configured",
    mcp_servers=["fetch", "filesystem"],
)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert any(item.kind == "dynamic_mcp_endpoint" for item in graph.coverage.diagnostics)
    assert not any(item.kind == "unresolved_tool" for item in graph.coverage.diagnostics)


def test_langgraph_symbolic_end_path_map_is_resolved(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(
        """
from langgraph.graph import END, StateGraph

def route(state):
    return END if state else "again"

builder = StateGraph(dict)
builder.add_node("again", lambda state: state)
builder.add_conditional_edges(
    "again",
    route,
    {"again": "again", END: END},
)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "builder")
    assert ("again", "again") in agent.metadata["control_edges"]
    assert ("again", "__end__") in agent.metadata["control_edges"]
    assert not any(item.kind == "unresolved_handoff" for item in graph.coverage.diagnostics)


def test_langgraph_toolnode_without_explicit_name_is_resolved(tmp_path: Path) -> None:
    (tmp_path / "graph.py").write_text(
        """
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

tools = []
builder = StateGraph(dict)
builder.add_node("call_model", lambda state: state)
builder.add_node(ToolNode(tools))
builder.add_conditional_edges("call_model", tools_condition)
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "builder")
    assert any(tool.name == "tools" for tool in agent.tools)
    assert not any(item.kind == "unresolved_handoff" for item in graph.coverage.diagnostics)


def test_invalid_python_in_explicit_snippets_directory_is_informational(tmp_path: Path) -> None:
    snippets = tmp_path / "resources" / "snippets_py"
    snippets.mkdir(parents=True)
    (snippets / "fragment.py").write_text(
        "this is intentionally not valid python !!!\n",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        """
from agents import Agent
agent = Agent(name="valid")
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    assert not any(item.kind == "parse_error" for item in graph.coverage.diagnostics)
    diagnostic = next(
        item for item in graph.coverage.diagnostics if item.kind == "source_fragment"
    )
    assert diagnostic.incomplete is False


def test_same_named_langgraph_builders_in_different_files_remain_distinct(tmp_path: Path) -> None:
    (tmp_path / "first.py").write_text(
        """
from langgraph.graph import StateGraph

builder = StateGraph(dict)
builder.add_node("first_a", lambda state: state)
builder.add_node("first_b", lambda state: state)
builder.add_edge("first_a", "first_b")
""",
        encoding="utf-8",
    )
    (tmp_path / "second.py").write_text(
        """
from langgraph.graph import StateGraph

builder = StateGraph(dict)
builder.add_node("second_a", lambda state: state)
builder.add_node("second_b", lambda state: state)
builder.add_edge("second_a", "second_b")
""",
        encoding="utf-8",
    )
    graph, _ = scan(tmp_path)
    builders = [agent for agent in graph.agents if agent.name == "builder"]
    assert len(builders) == 2
    by_file = {agent.location.path.name: agent for agent in builders}
    assert {tool.name for tool in by_file["first.py"].tools} == {"first_a", "first_b"}
    assert {tool.name for tool in by_file["second.py"].tools} == {"second_a", "second_b"}

    adg = graph.adg.as_dict()
    builder_nodes = [
        node for node in adg["nodes"]
        if node["kind"] == "agent" and node["name"] == "builder"
    ]
    assert len(builder_nodes) == 2
    control_edges = [edge for edge in adg["edges"] if edge["kind"] == "CONTROL_FLOWS_TO"]
    assert len(control_edges) == 2
