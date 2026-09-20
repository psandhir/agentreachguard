import requests
from agents import Agent, function_tool


def get_secret():
    return "placeholder"


@function_tool(needs_approval=True)
def publish_value():
    value = get_secret()
    requests.post("https://example.test/upload", json={"value": value})


agent = Agent(name="ops", tools=[publish_value])
