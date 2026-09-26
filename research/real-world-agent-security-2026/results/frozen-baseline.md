# HorusTrace Real-World Agent Security 2026 — Frozen Baseline

- Frozen scanner SHA: \`418db4e29798a7d25df686dd7bccfd9fefa225bd\`
- Cohort: 180 exact-SHA repositories
- Successful scans: 179
- Execution/fetch failures: 1
- Analysis-incomplete cases: 94
- Target applications were not installed, imported, or executed.
- Runtime effectiveness remains not verified.

## Structural and authority metrics

| Dimension | Precision* | Recall | Truth | Predicted |
| --- | ---: | ---: | ---: | ---: |
| Agent/workflow entities | 0.971 | 0.499 | 691 | 439 |
| Tools | 0.489 | 0.267 | 1110 | 731 |
| MCP servers | 0.000 | 0.273 | 22 | 10 |
| Delegation edges | 0.944 | 0.776 | 85 | 79 |
| Explicit effective authority | 0.278 | 0.611 | 126 | 304 |

\* Precision is computed only on cases where the independent reference explicitly marks the relevant dimension complete. Extra predictions on incomplete cases remain unadjudicated, not false positives.

## Attack paths

- Tier-B reported paths: 3
- Source-adjudicable reported paths: 0
- Source-supported: 0
- Structural support precision: None
- Known-path recall: not measured; the automated reference does not establish an exhaustive valid-path catalogue.

## Findings

- Findings: 268
- By severity: \`{"critical": 10, "high": 62, "medium": 196}\`
- Finding assertion precision/recall are not claimed from this automated reference.

## Tier C

- Defensible Tier-C cases: 4 / target 25
- Repository-declared identity recall: 0.0
- Runtime deployment effectiveness is not verified.

## Pre-registered threshold checks available from this reference

| Metric | Value | Threshold | Meets |
| --- | ---: | ---: | --- |
| agent_root_precision | 0.971 | 0.95 | yes |
| agent_root_recall | 0.499 | 0.90 | no |
| authority_edge_precision | 0.278 | 0.90 | no |
| authority_edge_recall | 0.611 | 0.80 | no |
| attack_path_structural_support_precision | n/a | 0.80 | no |

## Reference limitation

Ground truth was built by an independent automated dual-pass source reference (structural parser plus lexical cross-check) before scanner execution. It is not represented as an independent human dual-review panel. Dynamic constructs are unresolved, precision is restricted to completeness-marked cases, and finding semantics / exhaustive attack-path recall remain outside the claims supported by this baseline.

