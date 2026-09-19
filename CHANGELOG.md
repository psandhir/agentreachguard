# Changelog

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

## Unreleased

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
