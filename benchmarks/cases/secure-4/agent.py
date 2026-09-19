from agents import Agent, function_tool


@function_tool(needs_approval=True)
def publish_reviewed_summary(summary: str) -> str:
    return summary


agent = Agent(name="reviewer", tools=[publish_reviewed_summary])
