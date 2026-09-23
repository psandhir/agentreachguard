# Frozen 90 public-corpus baseline after PR #61

## Purpose

This report freezes the post-PR61 HorusTrace research baseline against the same 90 public repositories and exact target commit SHAs used by the prior frozen study. It is intended to make coverage changes measurable without conflating scanner evolution with repository drift.

- Target corpus frozen: **2026-09-22**
- Re-run date: **2026-09-23**
- Scanner commit: `69e7da8bf219520fd289f82606500fcbc4c19897`
- Repositories scanned: **90/90**
- Clone failures: **0**
- Scan errors: **0**
- Scan timeouts: **0**
- Coverage complete/incomplete: **39 / 51**

The scanner is static-first: target repositories are fetched at the pinned commits but are not imported, installed, or executed.

## Aggregate result

| Metric | Post-PR59 baseline | Post-PR61 baseline | Delta |
|---|---:|---:|---:|
| Agents | 1,862 | 2,076 | +214 |
| Tools | 3,272 | 3,413 | +141 |
| MCP servers | 556 | 556 | 0 |
| Flows | 213 | 213 | 0 |
| Proven agent-reachable flows | 6 | 6 | 0 |
| Proven non-agent flows | 108 | 175 | +67 |
| Unknown agent reachability | 99 | 32 | -67 |
| Attack paths | 25 | 25 | 0 |
| Static-dataflow-backed attack paths | 2 | 2 | 0 |
| Bound MCP references | 56 | 57 | +1 |
| Unbound MCP references | 500 | 499 | -1 |
| Findings | 844 | 890 | +46 |
| Critical | 18 | 18 | 0 |
| High | 145 | 156 | +11 |
| Medium | 681 | 716 | +35 |

## What changed

Two changes dominate the new baseline.

First, flow reachability classification became substantially more decisive without increasing flow volume: **67 flows moved from unknown to proven non-agent**, while total flows, proven agent-reachable flows, and static-dataflow-backed attack paths were unchanged.

Second, first-class `langchain.agents.create_agent` normalization broadened agent/tool discovery. The targeted frozen Santos repository moved from **1 bound / 2 unbound MCP references to 2 bound / 1 unbound** with no increase in its finding count. This is the expected PR #60 result.

## Interpreting the finding increase

The aggregate finding count increased by 46, but this should **not** be interpreted as 46 newly discovered production vulnerabilities.

The increase is highly concentrated:

| Repository | Agent delta | Tool delta | Finding delta | Adjudication |
|---|---:|---:|---:|---|
| `bytedance/deer-flow` | +82 | +65 | +37 | Predominantly test graphs; four remaining items are in a manual integration/support script. |
| `langchain-ai/deepagents` | +97 | +20 | +4 | All four are unit-test findings. |
| `langchain-ai/langgraph-swarm-py` | +12 | +22 | +4 | All four are examples/notebooks. |
| `pamelafox/issue-triager-agent` | +1 | +7 | +1 | One runtime `NET002` finding became visible. |

For deer-flow, `backend/scripts/manual_task_continuity_check.py` explicitly describes itself as a manual controlled integration check, yet the older finding source-role classifier labelled its four findings as runtime. This evidence directly motivated the follow-on source-context work to distinguish CLI and application-support code from deployed runtime code.

## Stability signals

Several security-critical measurements did **not** move:

- total flows remained **213**;
- proven agent-reachable flows remained **6**;
- static-dataflow-backed attack paths remained **2**;
- Critical findings remained **18**;
- all 90 repositories remained scanable with zero clone failures, scan errors, or timeouts.

This suggests the current change is primarily broader framework normalization and better reachability classification rather than a change in attack-path generation behavior.

## Reproduction

The frozen manifests are:

- `benchmarks/public-corpus/cohort-a-v1.json`
- `benchmarks/public-corpus/cohort-b-v1.json`
- `benchmarks/public-corpus/cohort-c-v1.json`

The research runner is `scripts/frozen_corpus_rescan.py`.

Example:

```bash
export HORUSTRACE_SCANNER_REF=69e7da8bf219520fd289f82606500fcbc4c19897

python scripts/frozen_corpus_rescan.py \
  --cohort a \
  --manifest benchmarks/public-corpus/cohort-a-v1.json \
  --output-prefix frozen-post61-a
```

Repeat for cohorts B and C. Each manifest pins every target repository to an exact commit SHA.

## Limitations

This is a coverage and static-evidence study, not a prevalence study of exploitable vulnerabilities. A finding can describe static policy risk, heuristic risk, or potential authority rather than verified runtime exploitability. Framework repositories, tests, examples, notebooks, tutorials, and integration harnesses are deliberately present in the corpus because they stress normalization and coverage; source context therefore matters when interpreting aggregate finding counts.

The reviewed benchmark's precision/recall measurements are scoped to the benchmark cases and should not be interpreted as population-wide precision or recall for arbitrary public agent repositories.
