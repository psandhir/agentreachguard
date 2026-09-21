from agents import Agent

billing = Agent(name="billing")
triage = Agent(name="triage", handoffs=[billing])
