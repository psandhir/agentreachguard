# AgentReachGuard Roadmap

AgentReachGuard is an alpha-stage static security analyser for AI agents. The roadmap is ordered around increasing confidence in **effective authority** and **attack-path** analysis rather than simply increasing rule count.

## Reliability milestone

Implemented in the working tree:

- Coverage counts and diagnostics in console, JSON, and SARIF.
- Strict CI failure for detected incomplete analysis.
- Version 1 manifest field/type validation and source locations.
- Regression tests for ordering, delegation cycles, cross-file resources,
  identity enrichment, shared tools, and policy/source interaction.

- Distinguish source observations, manifest declarations, and heuristic inferences
  in finding evidence, preserving source locations through delegation.
- Report control observations separately from unverified runtime effectiveness.
- Label capability combinations as potential paths with explicit limitations.
- Treat approval callbacks and literal function URLs as observations rather than
  blanket approval or enforced egress controls.
- Add versioned finding fingerprints and scoped suppressions that require a reason
  and expiry, with matched/stale/expired audit output.
- Add baseline generation that refuses accidental replacement and scans the full
  unsuppressed current state.
- Add an exact reviewed benchmark gate with precision, recall, coverage, and CI
  enforcement, plus three initial trust-boundary scenarios.
- Recognize supported static evidence for restrictive Bash policies, MCP tool
  allowlists, sandbox timeout/network/filesystem limits, and egress allowlist
  coverage without claiming runtime enforcement.

Next:

- Expand the benchmark from focused scenarios to sanitized representative projects
  and publish historical precision/recall trends before expanding adapters.

## v0.4 — Live GCP authority resolution

- Resolve deployed/runtime service-account identities.
- Query effective IAM through Cloud Asset Inventory / IAM Policy Analyzer.
- Expand predefined and custom roles into permissions.
- Model inherited organization/folder/project grants.
- Compare runtime permissions with inferred/declared agent capability requirements.
- Keep authenticated cloud analysis optional; static scans remain credential-free.

## v0.5 — Change-aware security analysis

- Add `agentreachguard diff <base>..<head>`.
- Detect newly introduced capabilities, data access, egress, identities, and delegated authority.
- Produce PR-focused SARIF/Markdown findings.
- Add change-aware handling for existing fingerprints and suppressions.

## v0.6 — Reachability and deployment context

- Enrich GCP reachability from deployment/resource configuration.
- Improve destination/resource scope modelling.
- Model production vs non-production trust boundaries.
- Add evidence for workload identity and credential provenance.

## Framework expansion

Planned as separate adapters with independent tests rather than generic regex support:

- Google ADK JavaScript/TypeScript.
- Google ADK Go.
- Google ADK Java/Kotlin.
- Additional agent frameworks based on contributor demand.

## Ongoing

- Map rules to OWASP Agentic/GenAI guidance and other relevant frameworks.
- Expand secure/vulnerable fixture corpus.
- Improve source locations and remediation quality.
- Keep false-positive rates conservative and findings explainable.
