from pathlib import Path

from horustrace.adapters.registry import detect_python_frameworks
from horustrace.effective_authority import effective_authority_report
from horustrace.scanner import scan


def test_custom_mcp_model_tool_loop_is_discovered_as_agent_root(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from mcp import ClientSession

class Agent:
    def __init__(self, session: ClientSession, provider):
        self.session = session
        self.provider = provider

    async def connect(self):
        tools = (await self.session.list_tools()).tools
        self.provider.set_tools(tools)

    async def run_turn(self, prompt):
        response = self.provider.send_user_message(prompt)
        while response.tool_calls:
            for call in response.tool_calls:
                await self.session.call_tool(call.name, call.arguments)
            response = self.provider.send_tool_results([])
        return response
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "model-tool-loop" in detect_python_frameworks(source)
    agent = next(
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    )
    assert agent.name == "agent"
    assert agent.metadata["discovery_basis"] == "model_tools_selection_dispatch"
    assert set(agent.metadata["discovery_signals"]) == {
        "model_call",
        "model_selection",
        "tool_catalogue",
        "tool_dispatch",
    }
    assert agent.tools == []
    assert agent.mcp_servers == []
    assert graph.adg is not None
    node = next(
        item
        for item in graph.adg.nodes
        if item.kind == "agent" and item.name == "agent"
    )
    assert node.attributes["discovery_basis"] == "model_tools_selection_dispatch"
    assert node.attributes["semantic_entity_kind"] == "agent"
    assert node.attributes["semantic_entity_id"] == agent.metadata["semantic_entity_id"]
    assert effective_authority_report(graph)["relationships"] == []


def test_openai_compatible_custom_tool_loop_is_discovered(
    tmp_path: Path,
) -> None:
    (tmp_path / "agent.py").write_text(
        """
from openai import OpenAI

class Agent:
    def __init__(self):
        self.llm = OpenAI()
        self.tools = []

    def call_tool(self, name, arguments):
        return {"name": name, "arguments": arguments}

    def run(self, messages):
        response = self.llm.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            tools=self.tools,
        )
        for call in response.choices[0].message.tool_calls:
            self.call_tool(call.function.name, call.function.arguments)
        return response
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    roots = [
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    ]
    assert [item.name for item in roots] == ["agent"]


def test_agent_named_class_without_model_selected_dispatch_is_not_promoted(
    tmp_path: Path,
) -> None:
    source = tmp_path / "helper.py"
    source.write_text(
        """
class Agent:
    async def connect(self):
        return await self.session.list_tools()

    async def invoke(self, prompt):
        return await self.model.invoke(prompt)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "model-tool-loop" not in detect_python_frameworks(source)
    assert not any(
        item.metadata.get("framework") == "model-tool-loop"
        for item in graph.agents
    )


def test_livekit_tool_bound_agent_constructor_is_discovered(
    tmp_path: Path,
) -> None:
    source = tmp_path / "voice.py"
    source.write_text(
        """
from livekit.agents import Agent

realtime_agent = Agent(
    instructions="help",
    llm=realtime_model,
    tools=tools,
)

pipeline_agent = Agent(
    instructions="help",
    llm=standard_model,
    tools=tools,
)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "model-tool-loop" in detect_python_frameworks(source)
    agents = [
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
    ]
    assert [item.name for item in agents] == ["realtime_agent", "pipeline_agent"]
    assert len({item.metadata["instance_key"] for item in agents}) == 2
    assert graph.adg is not None
    adg_agents = [
        item
        for item in graph.adg.nodes
        if item.kind == "agent"
        and item.framework == "model-tool-loop"
        and item.name in {"realtime_agent", "pipeline_agent"}
    ]
    assert len(adg_agents) == 2
    assert all(
        item.metadata["discovery_basis"] == "explicit_tool_bound_agent_constructor"
        for item in agents
    )


def test_openai_agents_sdk_is_not_duplicated_by_generic_adapter(
    tmp_path: Path,
) -> None:
    source = tmp_path / "agent.py"
    source.write_text(
        """
from agents import Agent, function_tool

@function_tool
def search(query: str) -> str:
    return query

agent = Agent(name="support", tools=[search])
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "openai-agents" in detect_python_frameworks(source)
    assert "model-tool-loop" not in detect_python_frameworks(source)
    assert not any(
        item.metadata.get("framework") == "model-tool-loop"
        for item in graph.agents
    )


def test_unrelated_tools_keyword_does_not_prove_model_tool_exposure(
    tmp_path: Path,
) -> None:
    source = tmp_path / "helper.py"
    source.write_text(
        """
class Agent:
    def prepare(self):
        helper.configure(tools=self.registry)

    def run(self, prompt):
        response = self.model.invoke(prompt)
        for call in response.tool_calls:
            self.session.call_tool(call.name, call.arguments)
        return response
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    assert "model-tool-loop" not in detect_python_frameworks(source)
    assert not any(
        item.metadata.get("framework") == "model-tool-loop"
        for item in graph.agents
    )


def test_same_named_explicit_agent_branches_remain_distinct_in_adg(
    tmp_path: Path,
) -> None:
    source = tmp_path / "voice.py"
    source.write_text(
        """
from livekit.agents import Agent

if realtime:
    agent = Agent(llm=realtime_model, tools=tools)
else:
    agent = Agent(llm=standard_model, tools=tools)
""",
        encoding="utf-8",
    )

    graph, _ = scan(tmp_path)

    roots = [
        item
        for item in graph.agents
        if item.metadata.get("framework") == "model-tool-loop"
        and item.name == "agent"
    ]
    assert len(roots) == 2
    assert len({item.metadata["instance_key"] for item in roots}) == 2
    assert graph.adg is not None
    nodes = [
        item
        for item in graph.adg.nodes
        if item.kind == "agent"
        and item.framework == "model-tool-loop"
        and item.name == "agent"
    ]
    assert len(nodes) == 2
    assert len({item.node_id for item in nodes}) == 2
    assert {item.location["line"] for item in nodes} == {5, 7}
