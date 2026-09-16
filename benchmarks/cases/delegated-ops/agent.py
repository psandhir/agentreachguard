from google.adk import Agent
from google.adk.tools.bash_tool import ExecuteBashTool

worker = Agent(name="worker", tools=[ExecuteBashTool()])
root_agent = Agent(name="coordinator", sub_agents=[worker])
