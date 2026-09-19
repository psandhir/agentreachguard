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
5. **Attack-path analysis** — potential risk combinations such as untrusted content → delegated agent → shell, or confidential data → agent → external write.

> Status: **v0.2 beta / pilot-ready**. Findings are deterministic within supported constructs. AgentReachGuard does not prove runtime exploitability or complete live cloud authority.

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

AgentReachGuard v0.2 understands security-relevant ADK composition rather than only matching `Agent(...)`.

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

List the built-in rule catalogue without scanning a project:

```bash
agentreachguard rules
agentreachguard rules --format json --output rules.json
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

Malformed, unreadable, or structurally invalid policy manifests stop the scan with exit
code 1 and an error on stderr. This also applies with `--fail-on none`; that option
only disables failure for security findings. No report is written for a failed scan.

### Coverage and strict CI

```bash
agentreachguard scan . --strict --format json --output report.json
```

All report formats include file counts and coverage diagnostics. JSON exposes a
`coverage` object; SARIF exposes coverage in run properties and diagnostics as tool
execution notifications. Console output separates coverage from findings by layer.
`--strict` returns exit code 1 for detected incomplete analysis, regardless of
`--fail-on`. Unlike a fatal manifest error, incomplete analysis still writes the
report so CI can retain the diagnostics. Security threshold failures return exit
code 2; incomplete analysis takes precedence in strict mode.

Diagnostics use stable `ARG-COV-*` identifiers and currently cover read/parse
failures, unresolved Python tool/MCP references, unresolved delegation, dynamic
agent configuration sequences or expanded keyword arguments, unresolved external
helper semantics, dynamic MCP endpoints/tool filters, and scans with no supported
security targets.
Files in default ignored directories, and subtrees containing an
`.agentreachguard-ignore` marker, are excluded from file counts. Other unsupported
file types are counted as skipped. A scanned file was read and parsed;
that count does not mean its entire application behavior was understood.

No detected coverage gaps is not proof of complete analysis. Runtime-generated
behavior, arbitrary function semantics, cloud authorization, and control effectiveness
remain outside these diagnostics. A clean report means no supported rules triggered.

### Fingerprints, baselines and suppressions

Every finding has an `arg-v1:` fingerprint based on its rule, agent, repository-relative
path, and evidence. Line numbers and checkout roots are excluded, so fingerprints
survive routine source movement and different CI workspaces. A material evidence or
scope change produces a new fingerprint.

Create an initial baseline of current findings:

```bash
agentreachguard baseline . \
  --output .agentreachguard.suppressions.yaml \
  --reason "Initial adoption backlog SEC-42" \
  --expires 2026-12-31
```

Baseline creation scans without applying existing suppressions. It requires a reason
and a non-past expiry and refuses to replace an existing file unless `--force` is
passed. It also refuses to write when coverage diagnostics show incomplete analysis.
Review the generated entries before committing them; a baseline records
temporary risk acceptance rather than making the findings safe.

Suppression files use this schema:

```yaml
version: 1
suppressions:
  - id: accepted-shell-migration
    reason: Temporary migration path owned by SEC-42
    expires: 2026-12-31
    fingerprint: arg-v1:0123456789abcdef01234567
    rule_id: AGT020
```

A fingerprint is the narrowest scope. A rule suppression without a fingerprint must
also specify `agent` or a repository-relative `path` glob. IDs, reasons, and expiry
dates are mandatory; unknown fields and duplicate IDs or YAML keys fail closed.
IDs use letters, digits, dots, underscores, and dashes; reasons are single-line;
path scopes cannot be absolute or escape the scan root.
Expired entries never hide findings. Stale, matched, and expired entries remain in
console, JSON, and SARIF audit output. `--strict` also fails when an exception has
expired. Use `--suppressions path/to/file.yaml` to select a non-default file.

### Reviewed benchmark

```bash
agentreachguard benchmark benchmarks/cases.yaml
```

The reviewed corpus declares the exact `RULE@agent` findings expected for each case.
Unexpected findings are measured as false positives and missing findings as false
negatives. The v0.2 corpus contains 26 reviewed scenarios across secure, execution,
delegation, MCP, identity, data/network, attack-path and dynamic/unresolved analysis.
One case intentionally expects incomplete analysis and an exact coverage diagnostic;
all other cases fail on incomplete coverage. The command exits nonzero on any drift
and supports `--format json` for CI artifacts. See
[`benchmarks/README.md`](benchmarks/README.md).

### Evidence and control semantics

Findings retain their rule IDs and severity thresholds and now include:

- `assessment`: `static_configuration`, `policy_violation`, `heuristic_risk`, or
  `potential_risk`.
- `provenance`: facts with a subject, origin, and source location. `observed` means
  a supported static configuration was discovered; `declared` means a manifest
  assertion; `inferred` means a heuristic or derived relationship.
- `limitations`: uncertainty about runtime authority, controls, and exploitability.

Configuration findings include local evidence; aggregate capability/data/path
findings include agent context, which is not a formal data-flow trace. A manifest
policy violation may involve declared or inferred capabilities; it does not establish
runtime authority. Function capabilities are heuristic, while recognized built-in
capabilities follow the scanner's supported static semantics.

`control_observations` in JSON and SARIF distinguish approval configuration,
callback hooks, plugin-name inference, sandbox configuration, and possible network
destinations. For supported ADK and MCP configuration, they also record static
evidence of sandbox timeout/network/filesystem limits, Bash allowlist plus blocklist
policies, MCP tool allowlists, and whether every discovered egress destination fits
a declared allowlist. Their runtime effectiveness is always `not_verified`.
Callback or plugin presence can satisfy a missing-hook rule, but does not prove that
arbitrary callback/plugin code authorizes actions safely. Approval callbacks alone
do not establish an approval requirement. Mixed hosted-MCP approval policies are
treated as unknown rather than blanket approval.

Attack paths are labeled potential risks with `basis: capability_cooccurrence` and
`exploitability: not_verified`. Their severity reflects potential impact, not proven
exploitability. A literal URL inside a function establishes a possible destination,
not an egress allowlist; such functions now trigger the missing-restriction rule.
No runtime enforcement is inferred from those literals.

### Manifest schema

Manifests support schema version `1`. Omitting `version` retains the legacy v1
behavior. Unknown fields, unsupported versions, duplicate YAML keys, invalid nested
types, cyclic YAML aliases, and negative capability limits are rejected. Approval,
guardrail, authentication, and restriction fields require actual booleans;
capability/scope fields accept strings or lists of strings. Policy errors identify
the field and source line/column without printing its value. Existing documented
field aliases remain supported. The schema definitions live in
[`manifest_schema.py`](src/agentreachguard/manifest_schema.py).


## ADK-specific rule highlights

- `ADK001` — privileged ADK agent lacks a detected tool-control callback/plugin/confirmation boundary.
- `ADK002` — unsafe local code executor.
- `ADK003` — `LocalEnvironment` exposes local shell/file I/O.
- `ADK004` — bash execution without a detected restrictive `BashToolPolicy`.
- `ADK012` — sandboxed code execution lacks an explicit timeout, network, or filesystem limit.
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
- uses: psandhir/agentreachguard@main  # pre-release; use @v0.2.0 after the tag is published
  with:
    path: .
    fail-on: high
    strict: "true"
    suppressions: .agentreachguard.suppressions.yaml
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

### Repository scanner configuration

Use `.agentreachguard.yaml` to tune scanner policy separately from the security intent manifest and temporary suppressions:

```yaml
version: 1
scanner:
  strict: true
rules:
  ADK007: {severity: high}
  AGT022: {enabled: false}
```

Use `agentreachguard scan . --config path/to/config.yaml` to select a file explicitly. Disabled rules are reported separately from suppressions; severity overrides affect reporting and failure thresholds but not rule metadata or finding fingerprints.

### v0.2 release notes

v0.2 adds a rule catalogue, OWASP Agentic mappings as coverage references, explicit potential attack-path confidence, stable incomplete-analysis diagnostics, hostile-repository limits, path containment, and a 26-case reviewed benchmark with an expected-incomplete coverage case. These additions do not claim runtime control effectiveness or complete OWASP coverage. There are no intended breaking changes to documented v0.1 commands or manifest formats.
