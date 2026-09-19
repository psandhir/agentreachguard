from google.adk.agents import Agent


def build_tools():
    return []


root_agent = Agent(name="dynamic", tools=build_tools())
