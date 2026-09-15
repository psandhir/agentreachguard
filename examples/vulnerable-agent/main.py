from agents import Agent, ShellTool, function_tool


@function_tool
def read_confidential_report(report_id: str) -> str:
    return "confidential data"


@function_tool
def send_email(recipient: str, body: str) -> str:
    return "sent"


agent = Agent(
    name="Vulnerable finance analyst",
    instructions="Analyse finance documents and send results when asked.",
    tools=[read_confidential_report, send_email, ShellTool()],
)
