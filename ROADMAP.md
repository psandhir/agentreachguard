# AgentReachGuard Roadmap

AgentReachGuard is a **beta-stage / pilot-ready** static security analyser for AI agents. The roadmap is ordered around increasing confidence in **effective authority** and **attack-path** analysis rather than simply increasing rule count.

## v0.2 — Reliability and validation milestone

Completed in the v0.2 release candidate:

- Coverage counts and stable `ARG-COV-*` diagnostics in console, JSON, and SARIF.
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
- Versioned finding fingerprints and scoped suppressions requiring reason and expiry,
  with matched/stale/expired audit output.
- Baseline generation that refuses accidental replacement and scans the full
  unsuppressed current state.
- Structured rule metadata, rule catalogue CLI, and OWASP Agentic mappings.
- Explicit attack-path confidence semantics without claiming verified exploitability.
- Repository `.agentreachguard.yaml` configuration with rule enable/disable and
  severity overrides applied before suppressions.
- Hostile-repository protections including resource ceilings, canonical-path
  containment/deduplication, bounded diagnostics, and non-execution regression tests.
- A reviewed benchmark gate with 26 distinct scenarios, including expected incomplete
  analysis, with aggregate and per-rule precision/recall metrics.
- Immutable-SHA GitHub Actions dependencies and package/wheel smoke testing.

## Next reliability work

- Add sanitized representative real-world projects to the benchmark corpus.
- Publish benchmark history across releases rather than relying on a single snapshot.
- Expand false-positive traps and multi-file enterprise agent configurations.

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

- Maintain OWASP Agentic/GenAI and other relevant framework mappings.
- Expand secure/vulnerable fixture coverage.
- Improve source locations and remediation quality.
- Keep false-positive rates conservative and findings explainable.
