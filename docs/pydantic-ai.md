# Pydantic AI coverage

HorusTrace includes a first-class static adapter for Pydantic AI and Pydantic AI
Harness. The adapter parses Python source with the standard library AST and does not
import the target project, instantiate agents, connect to MCP servers, or execute tools.

## Supported agent configuration

The adapter recognizes:

- \`pydantic_ai.Agent(...)\` construction.
- Function tools registered with \`@agent.tool\` and \`@agent.tool_plain\`.
- Constructor tools passed through \`tools=[...]\`.
- Explicit \`Tool(...)\` wrappers.
- Static tool collections referenced through local list/tuple/set variables.
- Runtime \`toolsets=\` supplied to common agent run methods when statically resolvable.

Detected tools are normalized to HorusTrace capabilities so the existing five-layer
rules can reason about process execution, reads/writes, external writes, secrets,
network reachability, resource scope and delegation.

## Toolsets and approval

The adapter recognizes common \`FunctionToolset\` patterns, including:

- \`FunctionToolset(tools=[...])\`.
- \`@toolset.tool\` and \`@toolset.tool_plain\`.
- \`add_function(...)\` and \`add_tool(...)\`.
- \`CombinedToolset\`.
- \`ApprovalRequiredToolset\`.
- \`.approval_required()\` wrappers.
- common wrapper methods such as \`.filtered()\`, \`.prepared()\`,
  \`.defer_loading()\`, \`.include_return_schemas()\`, and \`.with_metadata()\`.

An unconditional \`requires_approval=True\` or an approval-required toolset without a
predicate is modeled as an explicit approval requirement.

Conditional approval is deliberately not treated as universal approval. Raising
\`ApprovalRequired\` inside a function, or supplying an approval predicate, is recorded
as conditional evidence but does not suppress findings that require every invocation
to be approval-gated.

Dynamic tool providers and filters that cannot be resolved statically produce coverage
diagnostics rather than being assumed safe.

## MCP

HorusTrace recognizes both current Pydantic AI MCP entry points:

- the higher-level \`MCP(...)\` capability;
- lower-level \`MCPToolset(...)\` toolsets.

Static URL and local-script endpoints are normalized to HorusTrace \`MCPServer\`
objects. Remote URL analysis feeds the existing MCP rules for transport, authentication
evidence and explicit tool allowlisting. Local Python/JavaScript script paths are
represented as stdio-backed MCP servers.

Provider-native \`MCPServerTool\` wrapped with \`NativeTool\` is also normalized when
its endpoint can be determined.

Dynamic clients, transports or endpoints remain coverage uncertainty.

## Capabilities and Harness

Security-relevant capabilities currently normalized include:

- \`FileSystem\`;
- \`Shell\`;
- \`ModalSandbox\`;
- \`WebSearch\`, \`WebFetch\`, and \`XSearch\`;
- \`BrowserUse\` and \`PlaywrightBrowser\`;
- \`ImageGeneration\`;
- \`SubAgents\` / \`Subagents\`;
- \`Advisor\`, \`Researcher\`, and \`Coder\`.

\`Coder\` is treated as a compound capability because it combines filesystem access,
shell execution, external reachability and agent delegation.

Selected provider-native tools wrapped by \`NativeTool\` are also normalized, including
web search/fetch, code execution, image generation, memory, file search and advisor
tools.

Control-oriented capabilities such as guardrails, prompt-injection protection, spend
limits, output limits and repair/history helpers are recorded as agent metadata. They
are not automatically treated as proof that privileged tool execution is safe.

## File and web trust modeling

A statically declared \`FileSystem(root)\` contributes a file resource scope. Broad
roots such as \`/\` can therefore reach Layer 4 resource-scope rules.

Web-search, web-fetch and browser capabilities add an untrusted web input source. This
lets attack-path analysis reason about combinations such as untrusted external content
plus command execution or state-changing tools.

## Coverage limitations

HorusTrace is intentionally conservative. It does not claim complete support for:

- runtime-generated agents, tools or capabilities;
- arbitrary dependency injection behavior;
- dynamically constructed toolsets and tool filters;
- custom \`AbstractToolset\` or custom capability implementations;
- runtime MCP authentication hidden inside pre-built FastMCP clients/transports;
- the effectiveness of guardrails, approval handlers, sandboxing or provider controls;
- live cloud/IAM authority not represented in source/IaC evidence.

Unsupported or dynamic security-relevant constructs should surface as coverage
diagnostics where HorusTrace can identify the uncertainty. A clean scan is not proof of
runtime safety.
