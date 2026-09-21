# Changelog

## Unreleased

## 0.4.0

- Publish the project as the `horustrace` PyPI distribution with the `horustrace` Python package and CLI.
- Retain `agentreachguard` as a compatibility CLI/package namespace and accept legacy configuration, manifest, suppression, and ignore filenames during the migration.
- Preserve existing `arg-v1:` finding fingerprints and legacy SARIF fingerprint keys alongside HorusTrace keys.
- Rename the open-source project from **AgentReachGuard** to **HorusTrace**. The PyPI distribution, Python package, CLI, configuration filenames, and existing finding fingerprints remain under the `agentreachguard` namespace until the package migration is completed.
- Add a versioned, deterministic Agent Dependency Graph (ADG) with typed nodes and
  relationships across agents, tools, models, prompt digests, memory, identities,
  resources, destinations, MCP servers, and policy controls.
- Add bounded cross-file source-to-sink analysis for supported Python constructs,
  including supported static paths to process execution, external sends, and
  agent-memory/checkpoint writes.
- Distinguish `supported` static data-flow attack paths from `potential`
  capability-co-occurrence paths without claiming runtime exploitability.
- Add `PATH007` for supported untrusted-input to persistent-memory write paths.
- Add SARIF code flows for supported static paths.
- Add `agentreachguard graph` and `agentreachguard aibom` export commands.
- Add initial LangGraph StateGraph normalization and OpenAI Agents handoff/delegation
  relationships.
- Add ADG and flow-analysis safety ceilings plus unresolved data-flow/handoff
  coverage diagnostics.


## 0.3.0

- Add repository-aware Google ADK analysis with cross-file tool, helper, delegation,
  identity, OAuth, MCP, and execution-boundary resolution.
- Resolve simple agent factories, nested workflow agents, local tool collections,
  conditional tool references, and common `append`/`extend` construction patterns
  without executing target code.
- Resolve static module constants used for MCP endpoints while retaining runtime
  endpoints as explicit incomplete-analysis diagnostics.
- Model ADK `ExecuteBashTool` built-in confirmation semantics and provider-managed
  code execution more accurately.
- Prevent delegated synthetic capabilities from creating duplicate execution findings
  while preserving potential attack paths through delegation.
- Reduce false positives from generic `.execute()` methods, arbitrary URL literals,
  dictionary lookups, and fixed managed-service destinations.
- Improve MCP authentication detection, including dynamic header dictionaries and
  `X-Goog-Api-Key`; report unknown authentication state as coverage uncertainty.
- Link repository OAuth helper scopes and credential evidence to the tools that use
  them.
- Restrict repository resolution to scanner-approved files so ignore rules, path
  containment, and hostile-repository limits remain authoritative.
- Add repository resolution metrics to coverage output.
- Expand public-repository regression coverage and correctness tests.
- Validate the release with 228 automated tests and the 26-case reviewed benchmark;
  the benchmark fixture corpus reports precision 1.000 and recall 1.000.

## 0.2.0

- Fix transitive delegation, classified tool-resource checks, source-location merging,
  identity enrichment, and shared-agent tool overlay isolation.
- Reject invalid manifests with versioned field/type validation and safe error reporting.
- Add coverage diagnostics and strict CI mode to all report formats and the GitHub Action.
- Add finding assessments, evidence origins and explicit static-analysis limitations.
- Report control observations with unverified runtime effectiveness.
- Describe inferred attack paths as potential capability combinations.
- Stop treating approval callbacks and literal function URLs as enforced controls.
- Add stable finding fingerprints, baseline generation, and scoped, reasoned,
  expiring suppressions with audit output.
- Add structured rule metadata, the `agentreachguard rules` catalogue command, and
  OWASP Agentic coverage mappings.
- Add explicit attack-path confidence values while retaining `not_verified` runtime
  exploitability semantics.
- Reject duplicate YAML repository-configuration keys and apply repository rule
  configuration before suppressions, with default/effective severity audit data.
- Bound coverage diagnostics, deduplicate canonical paths and symlink aliases, and
  report unresolved external helper semantics as `ARG-COV-008`.
- Expand hostile-repository regression coverage for deep/oversized YAML, malformed
  UTF-8, symlink loops, side-effecting Python, and non-executed MCP commands.
- Expand the reviewed benchmark to 26 materially different scenarios, including an
  expected-incomplete dynamic configuration case, with aggregate and per-rule metrics.
- Build and install the wheel in CI as a release smoke test.
- Pin GitHub Actions dependencies to verified immutable SHAs using current releases.

## 0.1.0

- Add first-class Google ADK Python static analysis.
- Add native ADK Agent Config YAML analysis.
- Model ADK workflow/sub-agent and AgentTool delegated authority.
- Add ADK MCP, A2A, code-execution, computer-use, BigQuery and Google API toolset analysis.
- Add callback/plugin/confirmation security-control discovery.
- Add Google OAuth/service-account/credential-source evidence into identity analysis.
- Add cross-file ADK delegation resolution.
- Add ADK-specific rules `ADK001` through `ADK011`.
- Add vulnerable and secure Google ADK reference fixtures.
- Expand regression suite to 32 tests.


## 0.3.0

Repository-level ADK analysis and public-corpus correctness fixes.

- Complete v0.3 public-corpus semantics: repository ignore parity, delegated control propagation, managed-service egress, loopback MCP context, auth-unknown coverage, provider-managed executor handling, resolution metrics, and helper/OAuth resolution.
