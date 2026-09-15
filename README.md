# AgentReachGuard

[![CI](https://github.com/psandhir/agentreachguard/actions/workflows/ci.yml/badge.svg)](https://github.com/psandhir/agentreachguard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

**Five-layer policy-as-code security analysis for AI agents.**

AgentReachGuard statically discovers agent configuration and evaluates five connected security layers:

1. **Agent configuration** — tools, approvals, guardrails, MCP, code execution and framework-specific controls.
2. **Capability analysis** — effective authority, capability budgets, prohibited actions and dangerous combinations.
3. **Identity & permissions** — cloud/IAM roles, wildcard permissions, OAuth scopes and credential source.
4. **Data & network reachability** — sensitive resources, resource scope, outbound destinations and allowlist violations.
5. **Attack-path analysis** — exploitable chains such as untrusted content → delegated agent → shell, or confidential data → agent → external write.

> Status: **v0.1 alpha**. Static findings are deterministic. The schema and rule catalogue may evolve before v1.0.

## Security model

```text
What is configured?
        ↓
What can the agent do directly or through delegation?
        ↓
What authority does its identity have?
        ↓
What data/resources/destinations are reachable?
        ↓
Which end-to-end attack paths exist?
```

The scanner is **static-first and local-first**. It does not import target Python modules and does not launch MCP servers or agents.

## Current framework/input coverage

- **Google Agent Development Kit (ADK) Python 2.x — first-class adapter**.
- **Google ADK Agent Config YAML** (`root_agent.yaml` and related agent configs).
- OpenAI Agents SDK Python constructs.
- Common MCP JSON configuration (`mcp.json`, `.mcp.json`).
- Framework-neutral `agentreachguard.manifest.yaml` for business/security intent.
- Terraform (`.tf`) for an initial GCP/Azure/AWS IAM view.
- ADK `.env` credential-source checks without exposing secret values in findings.

## Google ADK coverage

AgentReachGuard v0.1 understands security-relevant ADK composition rather than only matching `Agent(...)`.

### Agents and orchestration

- `Agent` / `LlmAgent`.
- `SequentialAgent`, `ParallelAgent`, `LoopAgent`.
- `sub_agents` and transitive delegated authority.
- `AgentTool` delegation and `include_plugins` isolation.
- `RemoteA2aAgent` consumption and `to_a2a(...)` exposure.
- transfer restrictions and workflow metadata.
- cross-file Python/config delegation aliases.

### Tools and execution

- plain Python functions used as ADK tools.
- `FunctionTool`, `LongRunningFunctionTool`, `AuthenticatedFunctionTool`.
- `require_confirmation`.
- `ExecuteBashTool` and `BashToolPolicy`.
- `EnvironmentToolset` / `LocalEnvironment`.
- `UnsafeLocalCodeExecutor`, `BuiltInCodeExecutor`, `AgentEngineSandboxCodeExecutor`, `GkeCodeExecutor`.
- `ComputerUseToolset`.
- BigQuery/Bigtable/Data Agent toolsets.
- Google API/Gmail/Calendar/Docs/Sheets/Slides/YouTube toolsets.
- search/retrieval tools and inferred untrusted external content.
- OpenAPI/API Hub/Application Integration/REST-style tool surfaces.
- memory/artifact/MCP-resource tools represented as data capabilities.

### MCP

- `McpToolset` / `MCPToolset`.
- stdio, SSE and Streamable HTTP connection parameters.
- URL/transport analysis.
- auth scheme/credential/header-provider detection.
- recognized authorization headers.
- tool filters.
- confirmation requirements.

### Safety controls

- `before_agent_callback`, `after_agent_callback`.
- `before_model_callback`, `after_model_callback`.
- `before_tool_callback`, `after_tool_callback`.
- model/tool error callbacks.
- security/safety/policy-style plugins attached through `App`/`Runner`.
- tool-level confirmation.

### Google identity context

- `google.auth.default(scopes=...)`.
- service-account-file use.
- ADK credentials config objects.
- Google API toolset `additional_scopes`.
- client-secret literals (reported without secret material).
- `.env` API-key/service-account-file indicators.
- Terraform GCP IAM bindings feeding Layer 3.

See [`docs/google-adk.md`](docs/google-adk.md) for the exact supported surface and limitations.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
agentreachguard scan .
```

### ADK demo

```bash
agentreachguard scan examples/google-adk-vulnerable --fail-on none
agentreachguard scan examples/google-adk-secure --fail-on none
```

The vulnerable ADK fixture intentionally exercises all five layers. The secure fixture should return zero findings under the current rule catalogue.

Generate SARIF:

```bash
agentreachguard scan . --format sarif --output agentreachguard.sarif --fail-on none
```

Fail CI on high/critical findings:

```bash
agentreachguard scan . --fail-on high
```

## ADK-specific rule highlights

- `ADK001` — privileged ADK agent lacks a detected tool-control callback/plugin/confirmation boundary.
- `ADK002` — unsafe local code executor.
- `ADK003` — `LocalEnvironment` exposes local shell/file I/O.
- `ADK004` — bash execution without a detected restrictive `BashToolPolicy`.
- `ADK005` — computer-use capability lacks an explicit action boundary.
- `ADK006` — BigQuery write capability is not statically blocked.
- `ADK007` — broad generated/API toolset without a tool filter.
- `ADK008` — delegated `AgentTool` disables inherited plugins.
- `ADK009` — remote A2A agent card uses plaintext HTTP.
- `ADK010` — remote A2A agent has no detected authentication.
- `ADK011` — privileged agent is exposed over A2A without a detected safety control.

These run in addition to the framework-neutral AGT/CAP/IDN/DATA/NET/PATH rules.

## Framework-neutral security manifest

The manifest declares business intent and runtime context that static source parsing cannot prove:

```yaml
version: 1
agents:
  - name: invoice-agent

    inputs:
      - name: supplier-portal
        kind: web
        trust: untrusted

    data:
      - name: invoices
        classification: confidential
        selector: /finance/invoices/**

    identities:
      - name: invoice-agent-sa
        provider: gcp
        roles: [roles/storage.objectViewer]
        resource_scope: projects/acme/buckets/invoices
        credential_source: workload_identity

    network:
      - target: https://erp.example.com/**
        restricted: true

    policy:
      required: [data.read, external.write, network.external]
      denied_capabilities: [process.execute, destructive.write]
      allowed_resources: [/finance/invoices/**]
      allowed_destinations: [https://erp.example.com/**]
      require_approval_for: [external.write]
      max_privileged_capabilities: 1
```

This enables least-privilege comparison between **required** and **effective** capabilities and lets Layers 4–5 reason about data and network paths.

## GitHub Action

```yaml
- uses: psandhir/agentreachguard@v0.1.0
  with:
    path: .
    fail-on: high
```

## Design principles

1. **Do not execute the target.** Static analysis must be safe on untrusted repositories.
2. **Separate observation from policy.** Adapters discover facts; policy adds business/security intent.
3. **Analyse effective authority.** Direct and delegated tool combinations matter more than isolated calls.
4. **Connect identity, data and egress.** Agent risk is an end-to-end property.
5. **Explain the path.** Findings include nodes forming the attack chain.
6. **Prefer deterministic CI findings.** Semantic/LLM analysis can be additive later.

## Scope boundary

The Google ADK adapter is intended to be comprehensive for **security-relevant static constructs in current Python ADK 2.x and native Agent Config YAML**. It is not a claim that arbitrary third-party tool implementations, dynamically generated Python, runtime cloud authorization, or separate Java/Go/JavaScript/Kotlin ADK SDK syntax is fully analysed. Those require dedicated adapters or runtime/cloud-control-plane enrichment.

AgentReachGuard is not a runtime firewall, formal taint verifier, malware scanner or proof that a prompt injection is exploitable. It does not execute the application or call cloud control planes during a normal scan.

## Project roadmap

See [ROADMAP.md](ROADMAP.md) for planned live GCP authority resolution, change-aware analysis, reachability enrichment, and framework expansion.

## Support

See [SUPPORT.md](SUPPORT.md).

## Security

See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
