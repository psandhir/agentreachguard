# Cohort B baseline — HorusTrace v0.4.1

This note records the first frozen baseline for HorusTrace public corpus **Cohort B**.

The purpose of Cohort B is not to maximise finding counts. It is to evaluate how well
HorusTrace reconstructs real agent systems, identify real security-relevant design
patterns, surface false positives and normalization gaps, and turn those gaps into
regression-tested improvements.

## Reproducibility

- Frozen manifest: `benchmarks/public-corpus/cohort-b-v1.json`
- Baseline scanner: `horustrace==0.4.1`
- GitHub Actions run: `35772336829`
- Repositories: 30
- All repositories pinned to exact commit SHAs before findings were reviewed
- Target repositories were cloned and statically inspected only
- No target dependencies were installed
- No target modules, agents, tools, or MCP servers were executed

## Aggregate result

```text
Repositories selected:      30
Preflight material:          30/30
Successfully scanned:        30/30
Scanner errors:              0
Scanner timeouts:            0

Complete static coverage:    15
Incomplete static coverage:  15

Agents:                      135
Tools:                       196
MCP servers:                 51
Identities:                  13
ADG nodes:                   343
ADG edges:                   243

Static flow paths:           2
Agent-mapped flow paths:     0
Attack paths:                2

Findings:                    50
  high:                      13
  medium:                    37
```

The most important result is not the 50 findings. Half of the cohort still encountered
explicit static-analysis coverage gaps, and neither of the two supported flow paths was
mapped back to a normalized agent. Those are direct improvement targets.

## Coverage by category

| Category | Repos | Complete | Incomplete | Agents | Tools | MCP | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|
| Google ADK | 8 | 3 | 5 | 41 | 59 | 2 | 16 |
| OpenAI Agents | 8 | 5 | 3 | 27 | 76 | 2 | 14 |
| LangGraph | 8 | 6 | 2 | 37 | 52 | 23 | 14 |
| MCP / mixed | 6 | 1 | 5 | 30 | 9 | 24 | 6 |

LangGraph currently has the strongest completeness rate in Cohort B. MCP/mixed is the
weakest, which is expected because many of those projects build their own framework,
configuration and runtime abstractions rather than using one of HorusTrace's deeper
first-class agent adapters.

## Most frequent findings

```text
AGT040  privileged tool lacks explicit guardrail/approval       11
AGT032  remote MCP lacks explicit tool allowlist                10
NET002  outbound capability lacks destination constraint         5
AGT030  remote MCP has no detected authentication                4
AGT050  unpinned MCP package execution                           4
CAP005  combined data-read and state-changing authority          3
IDN004  unsafe credential source                                 3
AGT022  state-changing tool without approval                     3
NET001  outbound reachability lacks detected restriction         2
AGT021  destructive action without human approval                2
PATH002 potential untrusted-input path to destructive action     2
ADK001  privileged ADK agent lacks detected tool control         1
```

These counts must not be interpreted as 50 confirmed vulnerabilities. Findings require
context and manual adjudication.

## First adjudication round

### Valid security finding — ADK RAG management agent

Repository:
`arjunprabhulal/adk-vertex-ai-rag-engine`

HorusTrace identified destructive corpus/file deletion tools without enforceable
approval and emitted `AGT021` and potential `PATH002` findings.

The source instructions explicitly say:

> Always confirm operations before executing them, especially for delete operations.

However, the delete tools are directly exposed to the ADK agent and HorusTrace finds no
tool-level confirmation, callback, plugin or equivalent enforceable control.

This is a strong example of an agent-security distinction:

```text
Prompt instruction: "confirm before deleting"
                 !=
Enforced approval at the privileged action boundary
```

The prompt is useful behavioural guidance, but it is not a security boundary.

Classification: **valid security finding**.

### False positive — loopback MCP treated as remote

Repository:
`docling-project/docling-mcp`

HorusTrace v0.4.1 emitted `AGT032` against:

```text
http://localhost:8000/mcp
```

`AGT032` is defined as a remote MCP allowlist rule. Existing `AGT030` and `AGT031`
already exempt loopback, but `AGT032` did not.

Classification: **false positive**.

Action: regression test and fix created in PR #21.

### False positive — template environment file

Repository:
`BitterSecurity/Decepticon`

HorusTrace emitted `IDN004` from `.env.example` placeholder content such as:

```text
GEMINI_API_KEY=your-gemini-key-here
```

An explicit example/template environment file is not evidence that the application
uses a hard-coded runtime credential.

Classification: **false positive**.

Action: regression test and fix created in PR #21.

### Context-dependent — public AWS Knowledge MCP

Repository:
`aws/agent-toolkit-for-aws`

The corpus detected an unauthenticated remote MCP endpoint:

```text
https://knowledge-mcp.global.api.aws
```

and no client-side tool allowlist.

The static observation is correct. Whether authentication is required depends on the
server's intended semantics; a public read-only knowledge service may deliberately
allow unauthenticated access.

Classification: **valid but context-dependent**.

This illustrates why HorusTrace findings should carry provenance and limitations rather
than being presented as confirmed vulnerabilities.

### Context-dependent — autonomous airline state changes

Repository:
`openai/openai-cs-agents-demo`

The Seat and Special Services Agent exposes seat-changing tools and its instructions
explicitly encourage autonomous execution when the required data is available.

HorusTrace reports state-changing authority without approval.

For a demo or a business process that deliberately permits autonomous seat changes this
may be acceptable. In another organisation, policy may require user confirmation before
a booking mutation.

Classification: **valid but context-dependent**.

This is a strong candidate for demonstrating the value of a
`horustrace.manifest.yaml` policy overlay.

## High-priority scanner gaps

### 1. Agent mapping for static flows

Cohort B:

```text
Static flow paths detected:  2
Mapped to an agent:          0
```

This remains one of the highest-value gaps. Static Python data flow and framework
normalization are currently separate enough that supported paths are frequently not
attached to the effective agent that can invoke the code.

### 2. Google Agents CLI scaffolding/templates

`google/agents-cli` contains extensive ADK scaffolding and templates:

- 151 Python files
- multiple ADK scaffold/template files detected during preflight

but v0.4.1 normalizes zero agents and emits substantial template/parse diagnostics.

The scanner is correctly exposing uncertainty, but the repository is a useful stress
case for distinguishing executable source from generated/template agent code.

### 3. OpenAI Agents custom abstractions

`qx-labs/agents-deep-research` passes OpenAI Agents preflight and HorusTrace discovers
three tools, but no agents are normalized.

This is a candidate for adapter enhancement or better framework-boundary detection.

### 4. Custom MCP/agent frameworks

Projects such as `QwenLM/Qwen-Agent` and `HKUDS/nanobot` contain substantial MCP
implementation but do not map cleanly into HorusTrace's framework-neutral agent model.

This is useful stress evidence, but should not be confused with first-class framework
support.

### 5. Dynamic configuration

Dynamic configuration is the dominant LangGraph/MCP coverage gap in this cohort.

Where configuration is truly runtime-derived, HorusTrace should continue to report
incompleteness rather than guess. Where common finite construction patterns are
statically resolvable, the adapters should improve.

### 6. MCP graph binding

The MCP/mixed cohort discovers 24 MCP servers but produces only four ADG edges in total.
That is a strong signal that endpoint discovery is currently ahead of contextual
binding to agents, tools, identities and resources.

## Initial research conclusions

The second cohort has already produced the desired outcome:

1. all 30 frozen repositories scan reliably;
2. real security-relevant authority problems are being detected;
3. context-dependent findings show why business policy matters;
4. false positives have been identified from real projects and converted into tests;
5. normalization/coverage gaps are measurable rather than hidden;
6. the next improvements can be prioritised using evidence from real application code.

The correct credibility claim at this stage is therefore not "HorusTrace found 50
vulnerabilities."

A defensible statement is:

> HorusTrace v0.4.1 successfully scanned a second frozen cohort of 30 public agent/MCP
> repositories with no scanner errors or timeouts, reconstructing 135 agents, 196 tools
> and 51 MCP servers. Manual adjudication has already identified both valid
> security-relevant findings and false positives, with the latter converted into
> regression-tested fixes. Static coverage was complete for 15 of the 30 repositories,
> making unresolved framework and dynamic-runtime semantics a documented area for
> further improvement.

## Next research steps

1. Complete a larger stratified manual adjudication set.
2. Merge validated Cohort B fixes.
3. Improve high-value normalization gaps, beginning with flow-to-agent mapping.
4. Re-run the identical frozen cohort against the improved scanner.
5. Produce the baseline-vs-improved delta.
6. Select 3–5 detailed case studies for publication.
7. Combine Cohorts A and B into the final 60-repository study.
