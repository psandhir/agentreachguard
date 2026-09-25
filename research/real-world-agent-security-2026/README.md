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

All 365 rows remain `pending`. Screening must inspect source/metadata, record include/exclude decisions and reasons, identify the application path for qualifying cases, and cross-check `previously_studied` before the candidate pool may be frozen. HorusTrace must not be run during this phase.
