# FastAgent static coverage

HorusTrace supports the decorator-driven Python API from FastAgent without
importing or executing the target repository.

## Supported constructs

The first-class FastAgent adapter recognizes:

- FastAgent(...) application instances;
- @fast.agent(...);
- @fast.custom(...);
- workflow decorators @fast.orchestrator, @fast.iterative_planner, @fast.router,
  @fast.chain, @fast.parallel, @fast.evaluator_optimizer, and @fast.maker;
- static workflow delegation targets such as agents, sequence, fan_out, fan_in,
  generator, evaluator, and worker;
- explicit local function_tools=[...] references;
- global @fast.tool declarations as unbound tools when no unique agent scope is
  statically proven;
- per-agent @agent_function.tool declarations when the decorated agent function
  resolves uniquely;
- explicit shell=True as local process-execution authority;
- human_input=True as a user input surface;
- static FastAgent MCP server names and MCP tool/resource/prompt filters as
  agent metadata.

FastAgent workflows reuse HorusTrace's framework-neutral delegation model, so
resolved workflow edges participate in the ADG and delegated-authority analysis.

## Conservative behavior

HorusTrace does not assume that a global @fast.tool is reachable by every
agent. It remains unbound unless the application explicitly provides a unique
static binding.

FastAgent servers=[...] entries are currently recorded as server references
rather than materialized MCP endpoints. Endpoint, transport, authentication and
credential authority can depend on fast-agent.yaml, AgentCards, runtime
attachment, or interactive /connect operations. Those surfaces require a
repository-level FastAgent configuration adapter before HorusTrace can claim
full MCP authority reconstruction.

Dynamic agent names, delegation collections and function-tool collections remain
explicit coverage gaps rather than being guessed.

## Scope boundary

This adapter covers static Python decorator composition. AgentCards, markdown
agent definitions, FastAgent YAML configuration, runtime MCP attachment,
dynamically loaded cards/plugins, and runtime model/provider authority are not
yet fully normalized.
