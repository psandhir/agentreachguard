# Architecture

AgentReachGuard v0.1 uses five analysis layers over one normalized security graph.

```text
ADK/OpenAI Python / ADK YAML / MCP / manifest / Terraform
                │
                ▼
        ┌─────────────────┐
        │ Layer 1         │
        │ Configuration   │
        └────────┬────────┘
                 ▼
        ┌─────────────────┐
        │ Layer 2         │
        │ Capabilities    │
        └────────┬────────┘
                 ▼
        ┌─────────────────┐
        │ Layer 3         │
        │ Identity / IAM  │
        └────────┬────────┘
                 ▼
        ┌─────────────────┐
        │ Layer 4         │
        │ Reachability    │
        └────────┬────────┘
                 ▼
        ┌─────────────────┐
        │ Layer 5         │
        │ Attack paths    │
        └────────┬────────┘
                 │
         ┌───────┼─────────┐
         ▼       ▼         ▼
      console   JSON      SARIF
```

## Normalized graph

Framework-specific adapters populate common objects:

- `Agent`
- `Tool`
- `MCPServer`
- `InputSource`
- `DataSource` / `ResourceScope`
- `Identity`
- `NetworkDestination`
- `AgentPolicy`
- `AttackPath`

Adapters must not execute the target application.

## Observation and policy

AgentReachGuard intentionally distinguishes between facts discovered from source/IaC and declarations that need business context.

For example, static code can discover `ShellTool`, but it cannot prove that shell access is required for the business purpose. The manifest therefore declares the capability budget and allowed resource/network boundary. Layer 2 and Layer 4 compare effective authority against that declared intent.

## Potential attack-path derivation

Layer 5 consumes facts from prior layers. Example:

```text
untrusted web input
      ↓
finance agent
      ↓
ShellTool
      ↓
process.execute
```

The potential path is only emitted when the normalized nodes and rule conditions are present.
It represents capability co-occurrence, not a verified data-flow trace or exploit.
Evidence origins survive source/manifest consolidation and delegated authority propagation.
Control observations describe detected configuration or hooks; runtime effectiveness remains unverified. PATH findings have an explicit confidence value. v0.2 emits `potential` only: it describes capability co-occurrence, not verified authority, executable flow, or exploitability. An outbound tool by itself is not treated as an inbound untrusted source.


## Google ADK composition

The ADK adapter normalizes direct tools, code executors, MCP toolsets and multi-agent delegation. `sub_agents` and `AgentTool` edges are propagated into synthetic delegated tools so Layers 2–5 evaluate authority reachable through a child, including transitive delegation. Native Agent Config YAML uses the same normalized graph.
