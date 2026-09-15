from agents import Agent, function_tool


@function_tool
def read_report(report_id: str) -> str:
    return "report"


@function_tool(needs_approval=True)
def send_email(recipient: str, body: str) -> str:
    return "sent"


agent = Agent(
    name="Secure finance analyst",
    instructions="Analyse approved finance documents.",
    tools=[read_report, send_email],
)
