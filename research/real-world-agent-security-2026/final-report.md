# HorusTrace Real-World Agent Security Study 2026 — Final Report

## Executive conclusion

The preregistered baseline study is complete through roadmap derivation for frozen HorusTrace scanner `418db4e29798a7d25df686dd7bccfd9fefa225bd`.

HorusTrace demonstrates **high precision when it recognizes agent roots**, but the major product weakness is **coverage and recall across heterogeneous real-world agent implementations**. The scanner is materially strongest on Google ADK and OpenAI Agents structural discovery, but it misses large portions of LangGraph, framework-neutral/MCP-custom, FastAgent, and several Pydantic AI patterns. Effective-authority reconstruction is not yet product-ready at the preregistered thresholds.

The study therefore supports a clear development direction: **do not add more policy rules first**. Improve semantic discovery, framework-neutral tool/MCP modeling, and authority binding before expanding the finding catalogue.

## Experimental controls

- Frozen HorusTrace SHA: `418db4e29798a7d25df686dd7bccfd9fefa225bd`
- Cohort: 180 exact-SHA public repositories
- Candidate universe reviewed: 381 repositories
- Qualified candidate pool: 196 repositories
- Baseline successful scans: 179
- Scanner/fetch failures: 1
- Analysis-incomplete cases: 94
- Previously unseen successful cases: 177
- Previously studied successful cases: 2
- Target applications were not installed, imported, or executed.
- No target credentials or live cloud/SaaS calls were used.
- Runtime effectiveness remains unverified.
- Ground truth was locked before scanner execution.

### Reference limitation

The locked source reference was produced by an independent automated dual-pass source process, not an independent human dual-review panel. Therefore this report claims precision only on completeness-marked dimensions. It does **not** claim finding assertion precision/recall, exhaustive attack-path recall, runtime exploitability, or live deployment effectiveness.

## Primary results

| Dimension | Precision | Recall | Preregistered threshold | Result |
| --- | ---: | ---: | ---: | --- |
| Agent/workflow entities | 0.971 | 0.499 | P≥0.95 / R≥0.90 | Precision met; recall missed |
| Tools | 0.489 | 0.267 | edge P≥0.90 / R≥0.85 | materially below |
| MCP servers | 0.000 | 0.273 | edge P≥0.90 / R≥0.85 | materially below |
| Delegation edges | 0.944 | 0.776 | edge P≥0.90 / R≥0.85 | precision met; recall missed |
| Effective authority | 0.278 | 0.611 | P≥0.90 / R≥0.80 | materially below |

The most important distinction is that agent-root precision is already strong: the scanner is generally conservative about declaring an agent. The dominant problem is what it fails to discover or connect.

## Framework breakdown

| Framework | Cases | Agent recall | Tool recall | MCP recall | Effective-authority recall | Findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Google ADK | 37 | 0.845 | 0.646 | 0.667 | 0.667 | 64 |
| OpenAI Agents | 31 | 0.821 | 0.422 | 0.000 | 0.483 | 58 |
| Pydantic AI | 34 | 0.674 | 0.539 | 0.000 | 1.000 | 29 |
| LangGraph | 35 | 0.250 | 0.068 | n/a | n/a | 71 |
| FastAgent | 3 | 0.344 | n/a | n/a | n/a | 0 |
| MCP/custom | 40 | 0.063 | 0.000 | 0.000 | n/a | 46 |

### Framework interpretation

**Google ADK is the strongest current adapter.** Agent recall of 0.845 is close to the 0.90 target and tool/MCP coverage is materially better than other strata. This should be treated as the reference implementation for adapter quality.

**OpenAI Agents has good root discovery but incomplete authority reconstruction.** Agent recall is 0.821, while tool recall falls to 0.422 and effective-authority recall to 0.483. The likely development focus is indirect tool registration, agent-as-tool/handoff structures, hosted/MCP tools, and binding agents to the exact tools they can invoke.

**Pydantic AI has moderate structural coverage but significant MCP/tool gaps.** Agent recall is 0.674 and tool recall 0.539. MCP recall is 0 despite source-confirmed MCP cases. Constructor-time MCP server collections, late initialization, and registration through agent methods/toolsets need explicit support.

**LangGraph is the largest structural discovery deficit.** It contributes 252 of the 346 missed agent/workflow entities (~73%) and has tool recall of only 0.068. Common real-world patterns include StateGraph nodes, ToolNode, create_react_agent/prebuilt executors, notebook-defined graphs, functions/classes used as graph nodes, and tools defined through LangChain decorators. Treating every graph node as an “agent” would be incorrect; the fix needs a LangGraph-specific semantic model that distinguishes workflow nodes, model-driven agent nodes, tool nodes, and deterministic control nodes.

**MCP/custom is the largest framework-neutral tool discovery deficit.** The stratum contains 408 of 814 missed tools (~50%). In 39 of 40 cases HorusTrace predicted no agent root, and in 39 of 40 it predicted no tool. A framework-name detector cannot solve this. HorusTrace needs a model-directed-loop abstraction that recognizes generic LLM→tool-schema→dispatch loops, MCP client session/list_tools/call_tool flows, remote/SSE/stdio server bindings, and hand-written tool registries.

**FastAgent remains both scarce and weakly covered.** Only three defensible ecosystem cases were found, and agent recall is 0.344. This is a real ecosystem-coverage constraint, but supporting the three genuine patterns is still worthwhile after the larger LangGraph/MCP-custom work.

## Effective authority

Across Tier-B truth:

- reference relationships: 126
- matched relationships: 77
- missed relationships: 49
- predicted relationships: 304
- measured precision on completeness-marked cases: 0.278
- recall: 0.611

Two distinct defects are visible:

1. **under-binding** — tools/agents are not discovered, so valid authority relationships disappear;
2. **over-binding** — discovered graph nodes/tools are connected too broadly, especially in LangGraph-style workflows.

This means authority accuracy cannot be fixed by tuning the policy layer. It must be fixed in graph construction and binding provenance.

## Delegation

Delegation is comparatively mature:

- precision: 0.944
- recall: 0.776
- truth edges: 85
- missed edges: 19

The remaining misses are concentrated in indirect handoff/delegation forms rather than a systemic false-positive problem.

## MCP

The study reference contains 22 explicit MCP servers. HorusTrace matched 6 and missed 16, for recall 0.273.

The failure is particularly important because MCP binding is central to the HorusTrace product thesis. The scanner currently detects some explicit framework-native MCP declarations but misses framework-neutral and constructor/list-based MCP configurations.

## Findings

The frozen scanner emitted 268 findings:

- critical: 10
- high: 62
- medium: 196

The most frequent rule IDs were:

- `AGT040`: 78
- `AGT020`: 51
- `CAP005`: 42
- `NET002`: 40
- `AGT022`: 18
- `ADK001`: 15
- `PATH001`: 10
- `NET001`: 5
- `AGT021`: 2
- `AGT032`: 2

These counts establish rule activity, not rule accuracy. Because the automated reference is not exhaustive enough to independently adjudicate every finding semantic, this study does not report finding precision or recall.

## Attack paths

The scanner produced 11 total attack paths, with 3 in Tier B. None were source-adjudicable under the locked automated reference, so structural-support precision and known-path recall are not established.

This is an evidence-quality limitation as well as a product signal. The next validation cycle needs a small human-adjudicated attack-path benchmark containing both valid paths and near-miss invalid paths before attack-path quality can be advertised quantitatively.

## Conservative uncertainty

There were 94 analysis-incomplete cases out of 179 successful scans. The effective-authority output contained 751 partially resolved relationships and no fully-resolved relationships on cases explicitly marked dynamic by the reference.

The study cannot calculate the preregistered unsupported-certainty rate from the automated reference. However, the scanner's use of partial resolution rather than silently asserting full certainty is directionally consistent with the product's conservative-evidence design.

## Deployment / IAM

Only 4 defensible Tier-C cases survived source review against a target of 25; this scarcity was preregistered as a reportable result.

Across those cases the source reference identified 7 repository-declared workload/deployer identities. HorusTrace matched 0 and missed 7, for identity recall 0.000.

This is a concrete regression/coverage gap for deployment identity reconstruction and should be fixed before expanding least-privilege policy semantics.

## Robustness

179/180 cases completed scanner execution. The single failure was `rw-177` (JUN176/exp-agent) due to an unreadable filesystem path causing an uncaught `PermissionError` during file traversal.

The scanner should treat unreadable paths like ignored/unavailable evidence, record a coverage diagnostic, and continue scanning.

## Generalization

177 of 179 successful cases were previously unseen. On that subset:

- agent precision: 0.970
- agent recall: 0.502
- effective-authority precision: 0.278
- effective-authority recall: 0.611

The baseline therefore reflects generalization rather than performance on a corpus that substantially influenced development.

## Error taxonomy

The measured failures reduce to six product-level categories:

1. **framework_root_discovery — critical frequency.** LangGraph dominates missed workflow/agent entities; MCP/custom often has no root at all.
2. **tool_discovery — critical frequency.** 814 source-reference tools were missed, half from MCP/custom.
3. **mcp_discovery / mcp_binding — high frequency and high strategic impact.** 16/22 explicit servers were missed.
4. **authority_binding — high security impact.** Both missing and over-broad relationships occur; LangGraph over-binding is particularly visible.
5. **deployment_identity — high security impact, smaller sample.** 0/7 source-declared identities matched in the Tier-C cohort.
6. **scanner_robustness — low frequency but must-fix.** One unreadable path crashed an otherwise static scan.

## Product-readiness conclusion

The current frozen scanner is **not yet ready to support a claim of comprehensive cross-framework agent authority reconstruction**. It is already useful for high-precision structural detection in supported patterns, particularly Google ADK, and it produces meaningful security graph/finding output when evidence is discovered.

The study indicates that the next product milestone should be defined by **recall and binding quality**, not by adding additional security rules.

## Study completion state

The preregistered workflow is complete through:

1. protocol freeze;
2. candidate discovery;
3. candidate screening;
4. candidate-pool and cohort freeze;
5. source-reference truth lock;
6. frozen baseline execution;
7. aggregate disagreement/error adjudication;
8. error taxonomy;
9. roadmap derivation.

Post-fix validation is intentionally a subsequent development cycle: fixes should be implemented against the error taxonomy, then the identical frozen cohort should be rerun without changing its truth artifacts.
