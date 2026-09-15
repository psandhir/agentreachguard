from google.adk import Agent
from google.adk.tools import FunctionTool
from google.adk.tools.bigquery import BigQueryToolset
from google.adk.tools.bigquery.config import BigQueryToolConfig, WriteMode
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams


def submit_approved_report(report_id: str):
    return {"submitted": report_id}

bq = BigQueryToolset(
    bigquery_tool_config=BigQueryToolConfig(write_mode=WriteMode.BLOCKED),
    tool_filter=["execute_sql"],
)

mcp = McpToolset(
    connection_params=StreamableHTTPConnectionParams(
        url="https://mcp.approved.example.com/mcp",
        headers={"Authorization": "Bearer runtime-token"},
    ),
    tool_filter=["read_reference_data"],
    require_confirmation=True,
)

submit = FunctionTool(submit_approved_report, require_confirmation=True)

root_agent = Agent(
    name="secure_adk_analyst",
    model="gemini-flash-latest",
    tools=[bq, mcp, submit],
    before_tool_callback=security_policy_gate,
)
