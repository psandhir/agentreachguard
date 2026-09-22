# Cohort C adjudication and value extraction

This document records the first manual review of the frozen Cohort C baseline
(`horustrace==0.4.1`) and identifies what the results demonstrate, what should
not be claimed, and which scanner improvements are directly supported by evidence.

## Study position after Cohort C

Across Cohorts A, B and C, HorusTrace has now been exercised against **90 frozen
public repositories**.

Aggregate scanner output across those three cohorts:

```text
Repositories scanned:     90 / 90
Scanner errors:             0
Scanner timeouts:           0

Agents normalized:       1,717
Tools normalized:        3,207
MCP servers discovered:    556
Identities discovered:       83

ADG nodes:               6,574
ADG edges:               5,527
Static flow paths:         207
Attack paths:               24
Raw findings:              889
```

The raw finding count is **not** a vulnerability count. The corpus deliberately
contains production-style applications, framework stress repositories, tutorials,
examples, notebooks, tests and templates.

Overall static coverage was complete for 40/90 repositories. That number is useful
as a product-maturity metric, but should not be presented as a security-effectiveness
rate because the stress repositories intentionally exercise dynamic and unsupported
patterns.

## Cohort C baseline

```text
Repositories:              30 / 30
Agents:                       276
Tools:                        779
MCP servers:                  170
Identities:                    36
ADG nodes / edges:     1,105 / 942

Findings:                     124
  Critical:                     2
  High:                        26
  Medium:                      96

Complete coverage:         11 / 30
Incomplete coverage:       19 / 30
Static flows:                  13
Agent-mapped flows:             0
Attack paths:                   2
```

Cohort C was intentionally harder than Cohort B. It contains more framework
integration libraries, runtime abstractions, dynamic MCP configuration, templates,
and production-style applications.

## Adjudicated findings

### 1. Valid code-execution risk — AWS sample calculator

Repository:
`aws-samples/sample-agentic-platform`

HorusTrace reported `AGT020` against an agent calculator in a notebook.

Manual review confirmed that the tool evaluates user-provided mathematical
expressions using:

```python
result = eval(expression)
```

This is a real code-execution sink reachable from an agent tool. The repository is a
sample/training environment, so this should be reported as **valid framework-stress
evidence**, not as a production vulnerability in an AWS service.

Classification: **valid security finding, non-production context**.

### 2. False positive — regex compilation treated as code execution

Repository:
`sondera-ai/trustworthy-adk`

HorusTrace reported `AGT020` because the email validator calls:

```python
re.compile(...)
```

The v0.4.1 ADK function analyzer classified any method whose leaf name was
`compile` as execution. Only bare Python `compile(...)` should carry that meaning.

Classification: **false positive**.

Action: regression-tested fix in PR #30.

### 3. Missed control semantics — LangGraph human approval

Repository:
`pamelafox/issue-triager-agent`

HorusTrace reports privileged write authority for issue mutation functions.

Manual review confirms that mutation is gated by a LangGraph `HumanInterrupt`:

```python
human_response = interrupt([request])[0]
```

and the mutation node exits unless the resulting decision contains:

```python
approved = True
```

This is an enforceable graph-level approval boundary that HorusTrace does not
currently project onto downstream write actions.

Classification: **finding overstates uncontrolled authority because a real control is
present but not modelled**.

Product implication: approval must become a graph/control semantic rather than only a
property on individual tools.

### 4. Missed control semantics — inline Slack publishing confirmation

Repository:
`andrewm4894/github-standup-agent`

The agent exposes `publish_standup_to_slack`, but the function itself requires
explicit confirmation:

```python
if not confirmed and not ctx.context.slack_publish_confirmed:
    return preview
```

Publishing occurs only after user confirmation establishes the required state.

HorusTrace currently reports the publisher as an uncontrolled privileged tool and
treats `confirm_slack_publish` as an independent tool rather than a control relation.

Classification: **real external-write capability with a missed inline approval
control**.

Product implication: identify common confirmation guards inside tool functions and
represent them as controls over the protected sink.

### 5. Policy-dependent state mutation — Redis customer context

Repository:
`rafaelpierre/openai-agents-redis`

HorusTrace reports `AGT022`, `AGT040` and `CAP005` because the customer-service
agent can update customer region and append interaction notes.

The static observation is correct: the agent has read/write authority. However, these
mutations are not equivalent to destructive deletion, payment execution, identity
changes or external publication.

Classification: **valid authority observation, risk level is business-policy
dependent**.

Product implication: the capability taxonomy needs finer write semantics rather than
treating all `data.write` as the same class of privileged action.

### 6. Intended broad retrieval — OpenCMO

Repository:
`Lling0000/OpenCMO`

Several agents receive `NET001` because they can search the public web.

Manual review confirms that broad retrieval is intentional. The CMO explicitly uses
Tavily/OpenAI web search and a Google-search crawler fallback.

Classification: **valid broad-network observation, expected business capability**.

This is exactly the type of finding that should be evaluated against a policy overlay:

```text
Observed: broad public-web retrieval
Policy:   permitted for marketing research
Result:   accepted authority, not a violation
```

### 7. Confirmed v0.4.1 false positives reproduced in Cohort C

Cohort C independently reproduced both false-positive classes already discovered in B:

- `hellotinah/financial_agent`: localhost SSE/MCP reported by remote-MCP rule
  `AGT032`.
- `redis-developer/adk-redis` and `Klavis-AI/klavis`: `.env.example`
  placeholders reported as hard-coded runtime credentials.

Action: both corrected in PR #21.

## Finding volume must be source-context aware

A major research observation is that HorusTrace currently scans all source contexts
similarly.

Examples:

- `raphaelmansuy/adk_training` produced 83 of Cohort C's 124 findings.
- reviewed `bytedance/deer-flow` findings originate in `backend/tests/`.
- the AWS `eval` finding occurs in a lab notebook.
- `vstorm-co/full-stack-ai-agent-template` produced 265 template-source coverage
  diagnostics.

Those are useful for testing scanner behavior, but they must not be mixed with
production runtime findings when publishing prevalence numbers.

HorusTrace should classify finding provenance as at least:

```text
runtime
test
example
tutorial
notebook
template/generated
unknown
```

The scanner can still report all of them, but summaries should separate
runtime-relevant observations from stress/research evidence.

## Repeated technical gaps across Cohorts B and C

### Flow-to-agent correlation

```text
Cohort B:  2 supported static flows, 0 mapped to agents
Cohort C: 13 supported static flows, 0 mapped to agents
```

This is now the clearest high-value technical weakness.

The flow engine can understand selected Python source/sink relationships, and framework
adapters can normalize agents/tools, but those two views are not being joined reliably.

### MCP contextual binding

```text
Cohort B MCP/mixed:
24 MCP servers, 4 ADG edges

Cohort C MCP/mixed:
131 MCP servers, 47 ADG edges
```

HorusTrace discovers MCP infrastructure much better than it reconstructs who can use
that infrastructure and under which authority.

### Control understanding

Three independent repositories now demonstrate control patterns beyond simple
`tool.approval=True`:

- LangGraph `HumanInterrupt`
- inline confirmation state/arguments
- ADK security plugins with different semantics

This justifies making controls first-class ADG objects with explicit scope and type.

## What the 90-repository study can credibly claim today

A defensible public statement is:

> HorusTrace has been exercised against 90 frozen public agent, framework and MCP
> repositories without scanner errors or timeouts. Across the corpus it reconstructed
> more than 1,700 agents, 3,200 tools and 550 MCP servers. Manual adjudication has
> identified genuine security-relevant authority patterns, context-dependent policy
> findings, and scanner false positives; the latter are being converted into regression
> tests and fixes. The study also documents important limitations in static coverage,
> control propagation, flow-to-agent correlation and dynamic MCP binding.

The study should **not** claim:

- 889 vulnerabilities were found;
- a raw finding rate represents industry prevalence;
- static coverage completeness proves application security;
- benchmark precision/recall generalizes to arbitrary repositories.

## Product value demonstrated by the study

The most important evidence is not the number of findings. The study demonstrates that
HorusTrace can repeatedly answer security questions conventional SAST does not model
well:

- what authority an LLM receives through its tools;
- whether remote MCP access is constrained;
- whether destructive or external actions have approval boundaries;
- how delegation expands effective capability;
- where identity/network/data authority combine;
- where static analysis cannot safely resolve runtime behavior.

At the same time, the corpus is exposing where HorusTrace needs deeper semantics rather
than more rules.

## Prioritized next work

The evidence supports this order:

1. **Flow-to-agent mapping**
2. **Approval/control propagation**
3. **Source-context classification**
4. **MCP-to-agent/identity/resource binding**
5. **Richer write/egress capability taxonomy**
6. **Framework-specific normalization gaps**

These priorities are tracked in Issue #31.
