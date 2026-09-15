# AgentReachGuard Roadmap

AgentReachGuard is an alpha-stage static security analyser for AI agents. The roadmap is ordered around increasing confidence in **effective authority** and **attack-path** analysis rather than simply increasing rule count.

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
- Add suppressions/baselines with explicit rationale and expiry.

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
