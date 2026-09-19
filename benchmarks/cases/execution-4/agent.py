from google.adk import Agent
from google.adk.code_executors import BuiltInCodeExecutor

root_agent = Agent(
    name="coder",
    model="gemini-flash-latest",
    code_executor=BuiltInCodeExecutor(),
)
