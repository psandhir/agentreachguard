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
