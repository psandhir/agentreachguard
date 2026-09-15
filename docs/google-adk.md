# Google ADK security coverage

AgentReachGuard v0.1 contains a first-class static adapter for Google Agent Development Kit (ADK) Python projects and native ADK Agent Config YAML.

## Analysis pipeline

```text
ADK Python / root_agent.yaml / Terraform / .env
                    │
                    ▼
       ADK syntax + composition discovery
                    │
                    ▼
       normalized AgentReachGuard security graph
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
      tools      identity    delegation
        │           │           │
        └───────────┼───────────┘
                    ▼
             five-layer engine
                    ▼
           findings + attack paths
```

## First-class constructs

### Agent composition

Recognized agent types:

- `Agent`
- `LlmAgent`
- `SequentialAgent`
- `ParallelAgent`
- `LoopAgent`
- `RemoteA2aAgent`

`sub_agents` and `AgentTool` relationships are converted into delegated effective authority. If a coordinator can delegate to a child with shell/network/write authority, those reachable capabilities are visible to capability and attack-path analysis.

### Function tools

Recognized wrappers:

- `FunctionTool`
- `LongRunningFunctionTool`
- `AuthenticatedFunctionTool`
- plain Python functions placed directly in `tools=[...]`

The adapter infers capabilities from names and selected operations in function bodies, including process execution, file I/O and external HTTP calls. Literal external URLs become network destinations.

### Execution

Recognized execution primitives:

- `ExecuteBashTool`
- `BashToolPolicy`
- `EnvironmentToolset`
- `LocalEnvironment`
- `UnsafeLocalCodeExecutor`
- `BuiltInCodeExecutor`
- `AgentEngineSandboxCodeExecutor`
- `GkeCodeExecutor`
- `ComputerUseToolset`

The graph records whether an executor is statically known to be sandboxed, and generic Layer 2/5 logic still evaluates the resulting execution authority and egress combinations.

### MCP

Recognized:

- `McpToolset` / `MCPToolset`
- `StdioConnectionParams`
- `StdioServerParameters`
- `SseConnectionParams`
- `StreamableHTTPConnectionParams`
- `tool_filter`
- `require_confirmation`
- `auth_scheme`
- `auth_credential`
- `header_provider`
- recognized Authorization/API-key headers

No MCP server is launched during analysis.

### Google/data/tool integrations

Security semantics are normalized for common Google and ADK toolsets including BigQuery, Bigtable, Data Agent, Google APIs, Gmail, Calendar, Docs, Sheets, Slides, YouTube, search/retrieval, API Hub, Application Integration, OpenAPI/REST, memory/artifact and MCP-resource tools.

`BigQueryToolConfig(write_mode=WriteMode.BLOCKED)` removes write authority from the normalized capability graph.

### Callbacks and plugins

The adapter observes agent/tool/model callbacks and security/safety/policy-style plugins attached through ADK application/runner constructs. These can satisfy selected control-presence rules; they do not prove the callback implementation is correct.

### A2A

The adapter models:

- `RemoteA2aAgent` as an external trust boundary;
- agent-card transport and detected auth configuration;
- `to_a2a(...)` as an inbound exposure point;
- delegated authority through child agents.

### Credentials and IAM

Static identity evidence includes:

- `google.auth.default(scopes=...)`;
- service-account-file usage;
- ADK credential config objects;
- Google API toolset OAuth scopes;
- client-secret literals without returning the secret value;
- selected `.env` credential indicators;
- GCP IAM bindings discovered by the Terraform adapter.

## Native Agent Config YAML

`root_agent.yaml` and ADK-like YAML configs are parsed without instantiating ADK objects. Tools, code executors, callbacks and sub-agent config paths are normalized into the same graph as Python-defined agents.

Cross-file child-agent references use source-path aliases as well as runtime names, so a parent config can inherit reachable capabilities from a child whose runtime `name` differs from its filename.

## Static-analysis boundary

AgentReachGuard does not execute dynamic factories, resolve live IAM inheritance, inspect the implementation of arbitrary third-party tools, or prove the semantic effectiveness of a callback/guardrail. Runtime-generated tool lists can require a manifest or future runtime enrichment.

Separate ADK language SDKs (JavaScript/TypeScript, Go, Java/Kotlin) require dedicated syntax adapters. They are not silently treated as fully analysed by the Python adapter.
