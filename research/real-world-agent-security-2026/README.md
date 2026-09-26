# Real-World Agent Security Study 2026

This directory contains the machine-readable state of the major HorusTrace validation study.

The study is deliberately phase-gated:

1. protocol;
2. candidate discovery;
3. candidate screening;
4. cohort freeze;
5. ground-truth lock;
6. baseline execution;
7. disagreement adjudication;
8. roadmap derivation.

The frozen baseline scanner is:

`418db4e29798a7d25df686dd7bccfd9fefa225bd`

Do not run HorusTrace on candidate repositories before the cohort and independent truth are frozen.

Files:

- `protocol.json` — pre-registered study design and thresholds;
- `candidates.json` — source-only candidate discovery/screening ledger; currently 365 unique exact-SHA repositories, all pending source/metadata screening;
- `cohort.json` — exact-SHA cohort; initially empty and unfrozen;
- `ground-truth.schema.json` — schema for case truth documents;
- `ground-truth/` — case truth documents after cohort freeze;
- `adjudication-notes/` — post-run disagreements/corrections without rewriting frozen truth;
- `results/` — immutable baseline and later post-fix artifacts.

The methodology is documented at `docs/research/real-world-agent-security-2026-methodology.md`.

## Candidate discovery snapshot

Phase 2 begins with a 365-repository source-only discovery snapshot:

- Google ADK: 75
- OpenAI Agents SDK: 65
- Pydantic AI: 65
- LangGraph: 65
- FastAgent: 30
- framework-neutral MCP/custom: 65

Each row records the immutable commit SHA plus the GitHub code-search query and evidence path that caused discovery. Discovery is deliberately over-inclusive: a match is not an inclusion decision.

Candidate screening is now in progress. The first balanced pilot reviewed 12 repositories (two from each original discovery stratum): 10 included, 2 excluded, 353 pending. One discovery match was re-stratified from FastAgent to LangGraph after source review showed that "FastAgent" was a project-local class name rather than use of the evalstate FastAgent framework.

Every completed screening record must be source-only and contain a rationale, license/provenance status, a defensible application path for included candidates, Tier B/Tier C eligibility signals, and a completed prior-study exposure check. HorusTrace must not be run during this phase.


## Screening pilot findings

The pilot validates several important screening rules before scaling review to all 365 candidates:

- discovery framework labels are provisional and may be corrected from pinned source;
- framework/library repositories are not automatically valid application cases;
- benchmark/integration adapters are not treated as agentic applications merely because they invoke an agent framework;
- a candidate may remain suitable for Tier A while not being sufficiently rich for Tier B or Tier C;
- absence of a GitHub-detected license is recorded explicitly rather than silently ignored;
- previous HorusTrace exposure is checked before a candidate is considered reviewed.

The candidate pool remains unfrozen. No cohort selection or HorusTrace execution has occurred.


## Screening batch 1

The first scaled screening batch reviewed 24 additional repositories using the same source-only rubric as the pilot.

Cumulative state after this batch:

- reviewed: 36
- included: 21
- excluded: 15
- pending: 329
- candidate pool frozen: no
- HorusTrace execution: none

The batch confirmed that the intentionally broad discovery process captures several classes of non-cohort material: framework/library internals, tutorial-only repositories, packaging formulas, benchmark simulations, MCP client utilities without an agent loop, and planned/documented integrations that are not implemented at the pinned revision.

It also confirmed that framework repositories can still contribute a case when a clearly bounded, substantive application example exists. For example, `Unfold-Security/pydantic-collab` is represented by its concrete multi-agent data-analysis pipeline example rather than by library internals.

A second LambChat repository was re-stratified from FastAgent to LangGraph and excluded as substantially identical to the previously screened LambChat variant. The original discovery stratum remains preserved in the discovery snapshot.


## Screening batch 2

The second scaled screening batch reviewed 24 additional repositories.

Cumulative state after this batch:

- reviewed: 60
- included: 34
- excluded: 26
- pending: 305
- candidate pool frozen: no
- HorusTrace execution: none

Batch 2 retained two genuine FastAgent applications after earlier discovery false positives had reduced that stratum: a Klavis Skybridge example and the AI Writers Workshop multi-agent/MCP integration.

It also retained `aws-samples/sample-agentic-platform` as the first especially strong Tier C candidate because the same pinned repository contains Pydantic AI application examples together with Terraform, Kubernetes/EKS and AWS deployment/identity context. Tier C eligibility is still provisional until dedicated deployment-source review.

As in earlier batches, documentation registries, SDK/library repositories, translated guides, MCP servers without an agent loop, and close project variants were excluded rather than counted merely because framework keywords were present.


## Screening batch 3

The third scaled screening batch reviewed 24 additional repositories.

Cumulative state after this batch:

- reviewed: 84
- included: 45
- excluded: 39
- pending: 281
- candidate pool frozen: no
- HorusTrace execution: none

Batch 3 added several high-value authority cases: a multi-agent AML/KYC system with read-only BigQuery access, an ADK research orchestrator using MCP plus sequential/parallel delegation, an OpenAI Agents SDK interpretation system inside PaintOmics, a LangGraph HITL stock-purchase example, and an autonomous ticket-to-PR coding pipeline.

`allen-stephen/memory-bank-samples` is retained as a strong provisional Tier C GCP case because the pinned repository contains the ADK application together with Agent Engine/Cloud Run deployment logic, service-account handling, and explicit GCP role grants.

`billyhargroveofficial/billyharness` was a false FastAgent discovery but a valid custom agent system. It was re-stratified to MCP/custom and retained because source shows a Go agent harness with MCP, gateway/TUI/Telegram surfaces, and shell/write-capable execution modes.

The FastAgent stratum continues to show substantial discovery noise. The study will report real scarcity if source screening cannot support the preregistered minimum rather than weakening inclusion criteria.


## Screening batch 4

The fourth scaled screening batch reviewed 24 additional repositories.

Cumulative state:

- reviewed: 108
- included: 56
- excluded: 52
- pending: 257
- candidate pool frozen: no
- HorusTrace execution: none

Retained cases add ADK multi-agent data-quality and media pipelines, a Vertex AI ADK + remote MCP governance example, OpenAI Agents identity/capability and MCP examples, an A2A multi-agent experiment, a real Pydantic AI portfolio assistant, LangGraph MCP/lead-generation workflows, and a custom MCP coding agent.

All four FastAgent discoveries in this tranche were research notes or editorial/review content rather than runnable FastAgent applications. This further strengthens the evidence that the discovery stratum is noisy and potentially scarce after source adjudication.

At the current cumulative inclusion yield (56 of 108 screened), substantially more screening is still required before a defensible 180-case cohort can be selected without weakening inclusion criteria.


## Screening batch 5

The fifth scaled screening batch reviewed 24 additional repositories.

Cumulative state:

- reviewed: 132
- included: 68
- excluded: 64
- pending: 233
- candidate pool frozen: no
- HorusTrace execution: none

Batch 5 retained several high-value security cases, including an ADK payment agent with confirmation-gated purchase authority, an enterprise datastore/OAuth ADK example, Pydantic AI agents with MCP/filesystem authority, a CTF LangGraph agent with Python/Binary Ninja tooling, and OpenLegion's multi-agent/MCP trust-boundary controls.

`omnigentx/jarvis` is a confirmed genuine evalstate FastAgent application and is retained in the FastAgent stratum. `RooCodeInc/Roomote` uses an internal custom subsystem named "fast-agent" but not evalstate FastAgent; it is re-stratified to MCP/custom and retained as a substantive custom cloud coding-agent system.

The corrected candidate-universe counts are now FastAgent 26 and MCP/custom 67. The original discovery snapshot remains unchanged.
