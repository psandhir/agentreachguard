# Rule catalogue

## Layer 1 — Agent/framework configuration

### Framework-neutral

- `AGT001` — broad local MCP filesystem scope.
- `AGT020` — shell/process execution without approval.
- `AGT021` — destructive action without approval.
- `AGT022` — state-changing tool without approval.
- `AGT030` — remote MCP without recognized authentication.
- `AGT031` — unencrypted remote MCP transport.
- `AGT032` — unrestricted remote MCP tool surface.
- `AGT040` — privileged tool without guardrail or approval.
- `AGT050` — unpinned MCP package execution.

### Google ADK

- `ADK001` — privileged ADK agent lacks a detected tool-control callback/plugin/confirmation boundary.
- `ADK002` — unsafe local ADK code execution.
- `ADK003` — `EnvironmentToolset` with `LocalEnvironment` exposes local shell/file I/O.
- `ADK004` — `ExecuteBashTool` lacks a detected restrictive `BashToolPolicy`.
- `ADK005` — computer-use capability lacks explicit action confirmation/guardrail.
- `ADK006` — BigQuery writes are not statically blocked.
- `ADK007` — broad ADK generated/API toolset has no detected tool filter.
- `ADK008` — `AgentTool(include_plugins=False)` may bypass inherited parent controls.
- `ADK009` — remote A2A agent card uses plaintext HTTP.
- `ADK010` — remote A2A agent has no detected authentication configuration.
- `ADK011` — privileged ADK agent is exposed over A2A without a detected safety control.

## Layer 2 — Capability analysis

- `CAP001` — effective capabilities exceed the declared capability budget.
- `CAP002` — explicitly denied capability is present.
- `CAP003` — high aggregate privileged authority.
- `CAP004` — command execution combined with external network access.
- `CAP005` — combined data read and state-change authority.
- `CAP006` — policy-required approval is not enforced.

## Layer 3 — Identity & permissions

- `IDN001` — broad administrative cloud/IAM role.
- `IDN002` — wildcard identity permission.
- `IDN003` — broad OAuth scope.
- `IDN004` — unsafe/static credential source.

## Layer 4 — Data & network reachability

- `AGT010` — sensitive data plus unapproved external write/network capability.
- `DATA001` — broad resource scope.
- `DATA002` — resource access exceeds declared allowlist.
- `DATA003` — sensitive data has broad/unconstrained egress reachability.
- `NET001` — unrestricted outbound network reachability.
- `NET002` — outbound capability has no destination constraint.
- `NET003` — destination exceeds declared network allowlist.

## Layer 5 — Attack paths

- `PATH001` — untrusted input to command execution.
- `PATH002` — untrusted input to destructive action.
- `PATH003` — sensitive data to external destination.
- `PATH004` — untrusted input plus sensitive data plus arbitrary execution.
- `PATH005` — untrusted input to secret access and egress.
- `PATH006` — untrusted input reaches multiple high-risk capability classes.
