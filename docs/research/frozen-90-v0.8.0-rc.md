# HorusTrace v0.8.0 release-candidate validation

This document records the pre-release validation performed for HorusTrace v0.8.0.

- Validation date: **2026-09-25**
- Product baseline: main at `4ee319f7abaffa73666f54b4fc7e703fffe641fb`
- RC validation branch: `release/v0.8-rc-validation`
- RC validation commit under frozen-corpus test: `80e878c3d078549499e7de8877c03c6889a620da`
- RC workflow run: **36103895497**
- Historical frozen-90 comparison run: **36036585304**
- Frozen targets: the same 90 repositories and pinned SHAs used by the v0.6 baseline

Target repositories were fetched at their frozen revisions. They were not imported,
installed or executed.

## Release-candidate test result

The release-candidate validation passed.

The standard regression suite passed on Python 3.11 and 3.12, including Ruff, pytest,
the HorusTrace benchmark, self-scan, the first-party reconcile Action, PR-diff Action,
package build, clean-wheel installation and CodeQL.

A separate clean-wheel validation exercised v0.8-specific behavior:

- aligned deployed authority succeeds;
- supported excess deployed authority returns the expected gate failure;
- deployment authority expansion returns the expected regression gate failure;
- privilege reduction is treated as an improvement rather than a regression;
- the installed wheel reports `horustrace 0.8.0`.

Permanent regression coverage also exercises an adversarial GCP case combining an
inherited excess role with a conditional Secret Manager grant, plus a missing-required-
permission case.

## Frozen-90 non-regression result

All three frozen cohorts completed successfully.

| Metric | v0.6 frozen baseline | v0.8 RC | Delta |
| --- | ---: | ---: | ---: |
| Repositories scanned | 90 / 90 | 90 / 90 | 0 |
| Scanner errors | 0 | 0 | 0 |
| Scanner timeouts | 0 | 0 | 0 |
| Clone failures/timeouts | 0 / 0 | 0 / 0 | 0 / 0 |
| Coverage complete / incomplete | 39 / 51 | 39 / 51 | 0 / 0 |
| Agents | 2,076 | 2,076 | 0 |
| Tools | 3,413 | 3,413 | 0 |
| MCP servers | 633 | 633 | 0 |
| Identities | 78 | 78 | 0 |
| Flow paths | 140 | 140 | 0 |
| Proven agent-reachable flows | 6 | 6 | 0 |
| Proven non-agent flows | 133 | 133 | 0 |
| Unknown agent reachability | 1 | 1 | 0 |
| Attack paths | 25 | 25 | 0 |
| Static-dataflow-backed attack paths | 2 | 2 | 0 |
| ADG nodes | 6,690 | 6,690 | 0 |
| ADG edges | 5,630 | 5,630 | 0 |
| Bound MCP declarations | 117 | 117 | 0 |
| Concrete unbound MCP declarations | 516 | 516 | 0 |
| MCP agent invokes | 117 | 117 | 0 |
| MCP identity edges | 3 | 3 | 0 |
| Approval-control nodes | 82 | 82 | 0 |
| Approval-guarded edges | 82 | 82 | 0 |
| Approved tools | 105 | 105 | 0 |
| Guarded tools | 41 | 41 | 0 |
| Findings | 1,105 | 1,105 | 0 |

The comparison was also performed at repository granularity. For all 90 repositories,
every field common to the historical v0.6 result and the current result was identical
after excluding scanner version and elapsed time. This includes rule/severity
distributions, coverage diagnostics, finding source contexts, flow/reachability data,
MCP-resolution data, attack-path data, trust-boundary classifications and OWASP
aggregation.

The current harness additionally records authority-resolution and policy-bootstrap
metrics that were not present in the historical v0.6 artifact:

- partially resolved authority relationships: **2,600**
- unresolved authority relationships: **2,600**
- policy-bootstrap agents: **2,076**
- policy-bootstrap agents with unresolved authority: **1,140**
- policy-bootstrap relationships observed: **2,600**

These are additional measurements and are not legacy metric drift.

## Deployment-authority validation boundary

The frozen public corpus does not contain the normalized deployment/IAM evidence needed
to validate v0.8 deployed-authority reconciliation. Therefore deployed-authority
behavior is validated by controlled regression fixtures and clean-wheel end-to-end
scenarios, while the frozen-90 study validates that the existing static-analysis
baseline did not regress.

All deployed-authority outputs continue to retain
`runtime_effectiveness: not_verified`.
