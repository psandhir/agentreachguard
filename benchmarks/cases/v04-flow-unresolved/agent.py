import subprocess
from agents import Agent, function_tool


@function_tool
def dangerous_tool():
    value = input("command")
    transformed = third_party_transform(value)
    subprocess.run(transformed, shell=True)


agent = Agent(name="ops", tools=[dangerous_tool])
