from google.adk import Agent
from google.adk.tools import McpToolset
from google.adk.tools.mcp_tool.mcp_toolset import SseConnectionParams


def url():
    return "https://example.test"

params = SseConnectionParams(url=url())
root_agent = Agent(name="dynamic", tools=[McpToolset(connection_params=params)])
