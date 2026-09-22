# HorusTrace 90-repository public study — research review

## Executive summary

HorusTrace has now been exercised against three public-repository cohorts totalling
**90 repositories**.

The study demonstrates strong scanner reliability and useful framework/security
normalization, but it also exposes several material limitations in static coverage
and semantic precision.

The most defensible headline is not the number of findings. It is that HorusTrace can
reliably process a broad and difficult real-world corpus, reconstruct substantial
agent/tool/MCP graphs, surface meaningful agent-security design issues, and explicitly
show where its analysis is incomplete.

## Aggregate study result

```text
Repositories scanned:         90 / 90
Scanner errors:                0
Scanner timeouts:              0

Agents normalized:          1,717
Tools normalized:           3,207
MCP servers discovered:       556
Identities:                    83

ADG nodes:                  6,574
ADG edges:                  5,527

Static flow paths:            207
Agent-mapped flow paths:        0
Attack paths:                  24

Complete static coverage:      40 / 90
Incomplete static coverage:    50 / 90

Raw findings:                 889
```

The 889 findings are **raw scanner observations**, not 889 confirmed vulnerabilities.

### Application vs framework-stress coverage

```text
Application repositories:        69
Complete application coverage:   36  (52%)

Framework-stress repositories:   21
Complete stress coverage:         4  (19%)
```

The stress repositories intentionally exercise framework internals, templates,
dynamic configuration and custom abstractions, so their lower completeness rate should
not be interpreted as application support failure.

## Cohort progression

### Cohort A

- 30 repositories: 21 applications + 9 framework-stress
- 14/30 complete
- 1,306 agents
- 2,232 tools
- 335 MCP servers
- 192 flow paths
- 0 mapped flows
- 715 raw findings

This cohort demonstrated that the architecture survives real repositories at scale.

### Cohort B

- 30 repositories: 24 applications + 6 framework-stress
- 15/30 complete
- 135 agents
- 196 tools
- 51 MCP servers
- 2 flow paths
- 0 mapped flows
- 50 raw findings

Cohort B introduced frozen SHAs, stronger manual adjudication and the first
before/after case-study method.

It directly exposed:
- loopback MCP false-positive semantics;
- template environment credential false positives;
- OpenAI runtime `agent.clone(mcp_servers=[...])` binding;
- missing OpenAI `create_static_tool_filter(...)` normalization.

### Cohort C

- 30 repositories: 24 applications + 6 framework-stress
- 11/30 complete
- 276 agents
- 779 tools
- 170 MCP servers
- 13 flow paths
- 0 mapped flows
- 124 raw findings

Cohort C was intentionally biased toward more integration-heavy repositories and
therefore produced a harder static-analysis workload.

## What the study demonstrates well

### 1. Scanner robustness

The strongest quantitative result is simple:

```text
90 repositories
0 scanner errors
0 scanner timeouts
```

HorusTrace can safely inspect unfamiliar repositories without importing or executing
target agent code.

### 2. Framework normalization works at meaningful scale

Across the study HorusTrace reconstructed:

```text
1,717 agents
3,207 tools
556 MCP servers
6,574 ADG nodes
5,527 ADG edges
```

This validates the core architectural choice of normalizing multiple agent frameworks
into a framework-independent security graph.

### 3. Useful agent-specific security findings are real

Manual review has validated several finding classes as genuinely useful.

#### Prompt-only confirmation is not an enforceable security boundary

In the ADK Vertex RAG management example, destructive corpus/file tools are exposed
directly to the agent.

The prompt tells the model to confirm operations, especially deletes, but no enforceable
tool approval boundary was detected.

This is precisely the distinction HorusTrace should make:

```text
"Ask before deleting" in a prompt
          !=
tool-level approval / callback / policy gate
```

#### MCP least-privilege findings

The Slack MCP case showed that:

```text
authenticated MCP connection
          !=
least-privileged MCP authority
```

An explicit client-side tool allowlist materially reduces the actions exposed to the
model.

The case also exposed and fixed OpenAI Agents runtime-clone and static-filter
normalization gaps.

#### Supply-chain observations

The corpus identified MCP launch patterns using unpinned package execution such as
`npx ... @latest`.

Those are useful agent/MCP supply-chain findings that ordinary application SAST may
not model as part of an agent authority graph.

### 4. Coverage uncertainty is valuable

HorusTrace does not silently turn unsupported runtime/dynamic constructs into a clean
result.

Across the study, major diagnostics include:

```text
unresolved_tool                    471
templated_source                   322
parse_error                        199
dynamic_configuration              101
unresolved_dataflow                 89
dynamic_mcp_endpoint                84
unresolved_delegation               40
external_helper_semantics           39
```

Some of these are scanner gaps; others are legitimate static-analysis boundaries.

Explicitly distinguishing the two is central to the project's credibility.

## What the study has exposed as weaknesses

### 1. Flow-to-agent correlation is the highest-priority architecture gap

Across all three cohorts:

```text
Static flow paths detected:   207
Mapped to an agent:             0
```

HorusTrace currently has two useful but insufficiently joined views:

```text
Python source-to-sink data flow
                 +

Framework-normalized agent/tool graph
```

The next major architecture step is to connect them.

Until that happens, many PATH findings must remain
`basis=capability_cooccurrence` rather than supported end-to-end agent-specific data
flow.

Tracked in issue #25.

### 2. Capability inference is sometimes too lexical

Cohort C exposed multiple cases where names or generic Python methods are interpreted
too aggressively.

Examples:

- `re.compile(...)` was interpreted as Python code execution;
- local `dict.update(...)` can establish `data.write`;
- helper names containing terms such as `publish` can be interpreted as external
  write capability despite only changing local confirmation state.

The `re.compile` defect is fixed in PR #24.

The broader issue requires capability provenance/confidence rather than treating every
heuristic capability as equally strong.

Tracked in issue #26.

### 3. Existing human-control mechanisms are not always understood

Three real patterns demonstrate this.

#### GitHub standup agent

`publish_standup_to_slack()` explicitly refuses to publish until confirmation is
present.

HorusTrace still sees an uncontrolled privileged tool.

#### OpenCMO

The Reddit/Twitter publishers use a double gate:

```text
confirm=True
       +
OPENCMO_AUTO_PUBLISH=1
```

and preview by default.

The current scanner does not treat those source-level checks as approval controls.

#### LangGraph issue triager

The workflow has a real:

```text
HumanInterrupt
    ->
approved decision
    ->
apply_decision
```

and `apply_decision` returns without mutation when approval is absent.

HorusTrace currently reports mutation authority without understanding that graph-level
control.

Tracked in issue #27.

### 4. Source role matters

Cohort C generated 124 raw findings.

A simple path-based review found:

```text
application/other       28
example/training        87
tests                    7
notebooks                2
```

The large ADK training repository alone contributes 83 findings.

Even excluding that outlier, 16 of the remaining 41 Cohort C findings are in obvious
tests/examples/notebooks.

This does not mean those findings should be discarded. It means research and CI output
must distinguish:

```text
production application code
test fixture
example/tutorial
notebook
template/generated source
```

Tracked in issue #28.

### 5. Network-destination semantics need refinement

Fixed literal destinations are currently stored as observed but
`restricted=False`.

That can make a hard-coded URL such as:

```text
https://www.google.com/search?q=
```

trigger high-severity `NET001` as though it were a broad destination.

There is still a useful distinction to report:

- wildcard/broad destination;
- runtime-dynamic destination;
- fixed literal destination;
- network-policy-enforced destination.

These should not all share the same severity/wording.

This work is tracked under the capability/precision issue #26.

### 6. Preflight/materiality also needs a tighter definition

The study uncovered repositories where framework names are present in project metadata
or external package configuration while the actual agent implementation is absent from
the repository.

For example, a repository may configure LangGraph through `langgraph.json` and package
metadata but contain only a tool-configuration UI locally.

Research preflight should therefore distinguish:

```text
framework mentioned/configured
             vs
framework implementation present in executable source
```

This is a research-harness lesson as well as a scanner-coverage lesson.

## Findings that are context-dependent, not vulnerabilities

Several useful findings depend on organisational policy.

Examples include:

- autonomous customer profile updates;
- automatic seat changes;
- public read-only MCP services without authentication;
- creating disposable browser/VM environments;
- network access to a known API host without a separate egress firewall policy.

HorusTrace is strongest when an organisation provides an explicit policy manifest so
the scanner can compare:

```text
observed effective authority
          vs
approved business authority
```

rather than relying only on generic secure-by-default rules.

## Finding concentration matters

Across 90 repositories, the most frequent raw rules are:

```text
AGT040   295   privileged tool lacks explicit control
CAP005   117   combined read/write authority
NET002   113   outbound capability lacks destination constraint
ADK001    89   privileged ADK agent lacks tool-control callback/plugin
AGT020    64   process execution without approval
AGT032    49   remote MCP lacks tool allowlist
CAP004    22   process execution + external network
NET001    21   broad/unrestricted destination
AGT022    20   state-changing tool without approval
PATH001   17   potential untrusted-input -> execution path
```

These counts are useful for prioritising scanner semantics, not for claiming prevalence
of vulnerabilities in the ecosystem.

The concentration of findings around privileged-tool controls also supports the central
HorusTrace thesis: **agent security is primarily an authority/control problem, not only
a vulnerable-line-of-code problem.**

## Current manual-adjudication categories

### Credible security findings

- destructive tools protected only by prompt instructions rather than enforceable
  approval;
- remote MCP/package execution using unpinned package versions;
- broad privileged actions where no approval/control boundary is visible;
- MCP tool surfaces that are authenticated but not explicitly narrowed.

### Valid but policy/context dependent

- low-impact business state changes without approval;
- public read-only MCP services;
- automatically created sandbox/VM resources;
- known outbound API destinations without network-level enforcement.

### Confirmed false positives or semantic gaps

- `.env.example` placeholders as runtime credentials — PR #21;
- localhost MCP treated as remote — PR #21;
- `re.compile` treated as code execution — PR #24;
- local state mutation treated as persistent/external write;
- source-level confirmation/HITL not recognized;
- fixed literal destinations described as broad/unrestricted.

## Engineering priorities produced by the study

### Priority 1 — graph truth

Issue #25:
join supported source-level data flow to normalized agent/tool ownership.

### Priority 2 — semantic precision

Issue #26:
add stronger capability provenance and separate local operations from external
authority.

### Priority 3 — control semantics

Issue #27:
recognize framework-native and source-level human approval consistently.

### Priority 4 — reporting credibility

Issue #28:
classify source role and split application findings from examples/tests/templates.

### Existing precision patches

- PR #21 — loopback MCP + environment-template false positives
- PR #24 — qualified `compile` calls vs Python built-in code execution

## What we can credibly claim publicly

A defensible statement today is:

> HorusTrace has been exercised against 90 frozen public agent and MCP repositories
> spanning Google ADK, OpenAI Agents SDK, LangGraph and mixed MCP architectures. The
> scanner completed all 90 repositories without errors or timeouts, normalizing more
> than 1,700 agents, 3,200 tools and 550 MCP servers into over 6,500 Agent Dependency
> Graph nodes. Manual review has validated useful findings around agent authority,
> destructive actions, MCP least privilege and supply-chain configuration, while also
> identifying false positives and coverage gaps that have been converted into
> regression-tested improvements.

We should **not** claim:

- 889 vulnerabilities were discovered;
- 100% precision or recall;
- 40/90 complete coverage means the remaining 50 are insecure;
- potential capability-cooccurrence paths are proven exploits;
- the public corpus represents prevalence across all production agent applications.

## Next experimental phase

The most valuable next step is not another 30 repositories yet.

1. Merge the precision fixes.
2. Implement source-role reporting.
3. Improve control recognition.
4. Start flow-to-agent correlation work.
5. Re-run Cohorts B and C at the exact frozen SHAs.
6. Measure:
   - false-positive reduction;
   - complete coverage change;
   - mapped-flow change;
   - ADG binding improvement;
   - finding deltas by rule/source role.
7. Publish 4–6 manually reviewed case studies.

Only after that should the corpus expand from 90 to 120 repositories.

That sequence turns the public corpus from a scan-count exercise into a repeatable
security-research programme.
