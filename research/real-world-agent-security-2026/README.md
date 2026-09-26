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


## Screening batch 6

The sixth scaled screening batch reviewed 24 additional repositories.

Cumulative state:

- reviewed: 156
- included: 77
- excluded: 79
- pending: 209
- candidate pool frozen: no
- HorusTrace execution: none

Retained cases include a multi-agent ADK cloud-architecture reviewer, Document AI OCR over sensitive documents, BigQuery + Fivetran MCP water-risk analysis, a confirmation/budget-bounded payment example, a Pydantic AI SQL agent, a multi-agent trading workflow, a LangGraph shell-execution example, a persistent/HITL travel planner, and a realtime voice agent with MCP banking tools.

All four FastAgent-labelled candidates in this tranche were analysis, metadata, specification, or digest content rather than runnable applications. After batch 6 the FastAgent stratum has 3 included cases, 19 excluded, and only 4 currently labelled candidates pending. Thus the preregistered minimum of 12 cannot be reached from the remaining FastAgent-labelled candidates alone; it would require future source-based re-stratifications into FastAgent. The study will preserve and report that coverage limitation if it remains at freeze time.

With 77 inclusions from 156 reviewed, the cumulative inclusion yield is now below 50%, so early cohort selection would be methodologically unsafe.


## Original candidate screening complete

Source-only adjudication of the original 365-repository discovery snapshot is complete.

Final screening state before any extension or cohort selection:

- reviewed: 365
- included: 180
- excluded: 185
- pending: 0
- candidate pool frozen: no
- HorusTrace execution: none
- included by corrected framework stratum:
  - Google ADK: 51
  - OpenAI Agents SDK: 23
  - Pydantic AI: 34
  - LangGraph: 36
  - FastAgent: 3
  - MCP/custom: 33

The original pool reaches 180 defensible applications, but it cannot itself become the final 180-case cohort without violating the preregistered Google ADK maximum of 40. It is also two cases below the OpenAI Agents SDK minimum of 25, while FastAgent remains materially below its preregistered minimum because the discovery stratum was dominated by catalogs, analysis, specifications, and unrelated name matches.

Accordingly, screening completion does **not** freeze the candidate pool. A bounded pre-freeze extension will target non-ADK applications, with priority on OpenAI Agents SDK and deployment/IAM evidence, before selecting the final balanced cohort. FastAgent criteria will not be weakened; any remaining FastAgent shortfall will be documented as a stratum exception.

The completion pass also corrected prior-study exposure provenance for four repositories found by cross-checking the frozen public-corpus and deployment-authority manifests. Two are included and two excluded. These corrections do not change selection decisions and allow later results to report previously unseen generalization separately.

No HorusTrace result was used in any screening decision.
