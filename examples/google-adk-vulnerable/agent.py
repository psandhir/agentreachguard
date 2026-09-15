from google.adk import Agent
from google.adk.code_executors import UnsafeLocalCodeExecutor
from google.adk.tools.bash_tool import ExecuteBashTool
from google.adk.tools.bigquery import BigQueryToolset
from google.adk.tools.computer_use.computer_use_toolset import ComputerUseToolset
from google.adk.tools.google_api_tool import GoogleApiToolset
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
from google.adk.tools import google_search

mcp = McpToolset(
    connection_params=StreamableHTTPConnectionParams(url="http://mcp.partner.example/mcp"),
)

bash = ExecuteBashTool()
bigquery = BigQueryToolset()
computer = ComputerUseToolset(computer=PlaywrightComputer())
google_api = GoogleApiToolset(
    additional_scopes=["https://www.googleapis.com/auth/cloud-platform"],
    client_secret="test-placeholder-not-a-real-secret",
)

privileged_worker = Agent(
    name="privileged_worker",
    model="gemini-flash-latest",
    tools=[bash, bigquery, computer, google_api, mcp],
    code_executor=UnsafeLocalCodeExecutor(),
)

root_agent = Agent(
    name="adk_coordinator",
    model="gemini-flash-latest",
    tools=[google_search],
    sub_agents=[privileged_worker],
)
