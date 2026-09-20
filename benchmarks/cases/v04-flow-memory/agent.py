from agents import Agent, function_tool


class Memory:
    def save(self, value):
        pass


memory = Memory()


@function_tool
def remember():
    value = input("value")
    memory.save(value)


agent = Agent(name="memory-agent", tools=[remember])
