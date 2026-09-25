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
