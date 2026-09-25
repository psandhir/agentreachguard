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
- `candidates.json` — candidate-screening ledger; initially empty;
- `cohort.json` — exact-SHA cohort; initially empty and unfrozen;
- `ground-truth.schema.json` — schema for case truth documents;
- `ground-truth/` — case truth documents after cohort freeze;
- `adjudication-notes/` — post-run disagreements/corrections without rewriting frozen truth;
- `results/` — immutable baseline and later post-fix artifacts.

The methodology is documented at `docs/research/real-world-agent-security-2026-methodology.md`.
