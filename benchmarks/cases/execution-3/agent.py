from google.adk import Agent
from google.adk.tools.computer_use.computer_use_toolset import ComputerUseToolset

computer = ComputerUseToolset(computer=object())
root_agent = Agent(name="browser", model="gemini-computer-use", tools=[computer])
