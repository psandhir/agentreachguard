# HorusTrace Real-World Agent Security Study 2026

## Purpose

This study evaluates HorusTrace as an agent-security product, not as a framework parser or a GCP IAM research prototype.

The primary question is:

> Can HorusTrace reliably reconstruct meaningful security properties of real agentic systems — including effective authority, MCP/tool reachability, delegation, approvals, identities, sensitive resources/destinations and attack paths — while remaining conservative when static evidence is insufficient?

Deployment/IAM reconciliation is one sub-study. It must not determine repository selection or dominate the headline evaluation.

The study freezes HorusTrace at commit `418db4e29798a7d25df686dd7bccfd9fefa225bd`, the post-PR #131 main revision. Production feature development is paused for the baseline study. Scanner crashes, study-harness defects, nondeterminism and HorusTrace security vulnerabilities may be fixed, but all such changes must be recorded and the original baseline retained.

## Why this study now exists

Previous research established several useful facts:

- the frozen-90 corpus is effective for scanner robustness and non-regression;
- the deployment-authority cohort showed that repository-declared workload identity/IAM reconstruction is tractable;
- positive required-authority evidence can prove missing authority;
- the frozen deployment cohort recovered all three pre-adjudicated missing IAM roles;
- negative/excess-authority claims require a completeness boundary rather than absence of positive evidence;
- a narrow Discovery Engine completeness experiment recovered the two independently adjudicated Discovery Engine excess roles without unrelated candidates;
- a product can discover valid evidence that a human adjudicator initially missed, so disagreements must be reviewed rather than automatically scored against either party.

Those results were valuable, but the deployment cohort began to influence feature selection directly. This study deliberately re-centres evaluation on the full HorusTrace product thesis.

## Frozen scanner

Primary baseline scanner:

- repository: `psandhir/horustrace`
- revision: `418db4e29798a7d25df686dd7bccfd9fefa225bd`
- package version in source: `0.8.0`
- freeze date: 2026-09-25

The SHA, not the package version string, identifies the experimental scanner.

The baseline study must not silently move to a later HorusTrace revision.

## Study structure

The study targets **180 unique public repositories**. All cases belong to the broad ecosystem cohort. Two overlapping deep-analysis subsets are pre-selected from source characteristics before HorusTrace execution.

### Broad ecosystem cohort — 180 repositories

Primary uses:

- scanner robustness;
- agent/workflow-root discovery;
- tool discovery;
- MCP discovery and binding;
- delegation topology;
- approval/control discovery;
- framework-specific coverage;
- coverage/unresolved diagnostics.

Framework targets:

| Stratum | Target | Minimum | Maximum |
| --- | ---: | ---: | ---: |
| Google ADK | 30 | 25 | 40 |
| OpenAI Agents SDK | 30 | 25 | 40 |
| Pydantic AI | 30 | 25 | 40 |
| LangGraph | 30 | 25 | 40 |
| FastAgent | 20 | 12 | 30 |
| Framework-neutral MCP / custom agent systems | 40 | 30 | 50 |
| **Total** | **180** |  |  |

If a stratum cannot meet its minimum after documented screening, the shortfall is reported as ecosystem coverage evidence rather than hidden. Remaining slots may be reallocated to other non-saturated strata without exceeding their maximums. Reallocation rules must be applied before HorusTrace execution.

### Deep authority / attack-path cohort — 60 repositories

A stratified subset of the broad cohort. Selection is based only on source-observed complexity criteria, not HorusTrace output.

Eligibility requires at least one of:

- multiple agents or explicit delegation/handoffs;
- MCP usage;
- code/shell/computer execution;
- sensitive data/resource access;
- external write/network capability;
- approval/confirmation controls;
- multiple trust boundaries;
- sufficiently complex tool composition to support authority-path adjudication.

This cohort receives dual-review ground truth for:

- effective agent-to-tool/MCP authority;
- delegated reachability;
- approval/control state;
- identities where statically evidenced;
- sensitive resources/destinations;
- security assertions;
- end-to-end attack paths and near-miss invalid paths.

The subset target is 60. At least four framework strata should contribute cases. No single framework may exceed 40% of the deep cohort unless candidate scarcity is documented before execution.

### Deployment / IAM cohort — 25 repositories

An overlapping subset where public source contains enough deployment or IaC evidence for workload-identity adjudication.

Provider is **not** an inclusion criterion. GCP, AWS, Azure, Kubernetes/service-account and other public deployment evidence may qualify. Unsupported provider semantics are measured as coverage gaps rather than excluded merely because HorusTrace cannot interpret them.

Primary adjudication dimensions:

- workload identity;
- deployed roles/permissions/scopes;
- source/deployment-backed required authority where defensible;
- missing authority;
- excess authority only where human evidence is sufficient;
- unresolved evidence;
- conditional/inherited/custom authority;
- distinction between repository-declared intent and live runtime state.

The target is 25. Failure to find 25 defensible public cases is itself reported.

## Candidate discovery and selection

The selection pipeline is:

```text
public candidate universe
        ↓
source/metadata screening
        ↓
candidate pool frozen
        ↓
cohort and exact SHAs frozen
        ↓
ground truth written and locked
        ↓
HorusTrace baseline execution
        ↓
disagreement adjudication
        ↓
error taxonomy
        ↓
roadmap
```

### Prohibited pre-selection information

Before the cohort is frozen:

- do not run HorusTrace against candidate repositories;
- do not use HorusTrace findings from previous exploratory runs to include or exclude a repository;
- do not select repositories because they are known to produce interesting HorusTrace findings;
- do not discard repositories because their framework/provider is currently unsupported;
- do not modify inclusion rules in response to expected scanner performance.

A repository previously present in HorusTrace research is not automatically excluded, but prior HorusTrace exposure must be tagged. Headline metrics will additionally be reported on the previously unseen subset.

### Broad inclusion criteria

A repository may enter the candidate pool when:

- it is public and fetchable;
- a specific immutable Git commit SHA can be pinned;
- it contains a real agentic application, framework example with substantive composition, or MCP-enabled agent system;
- relevant source is inspectable without executing the target;
- licensing/provenance permits public research;
- the selected revision is not generated solely for HorusTrace testing.

### Exclusion reasons

Every screened rejection must use a recorded reason such as:

- not actually agentic;
- trivial single-call example with insufficient security surface;
- duplicate/fork/substantially identical template;
- source unavailable at a stable revision;
- generated/minified-only source;
- repository too large for bounded static review without a defensible application path;
- licensing/provenance concern;
- malicious repository or unsafe content that cannot be reviewed under the study process.

Unsupported framework/provider is **not** by itself an exclusion reason.

## Ground-truth tiers

### Tier A — structural truth, all broad-cohort cases

At minimum:

- application path;
- framework(s);
- intended agent/workflow roots;
- explicit tools/toolsets;
- explicit MCP servers/references;
- explicit delegation/handoff edges;
- explicit approval/confirmation controls;
- explicit identities/credential context where visible;
- material unresolved/dynamic constructs.

Tier A supports discovery precision/recall and coverage analysis.

### Tier B — deep security truth, 60 cases

Each case records source-backed assertions with explicit evidence for:

- effective authority relationships;
- delegated reachability;
- MCP binding/tool filters;
- approval state;
- process/code/computer authority;
- data/resource access;
- network destinations;
- trust-boundary transitions;
- attack paths;
- deliberately adjudicated invalid near-miss paths;
- expected unresolved states.

Two reviews must be completed before HorusTrace execution. Reviewer disagreements are resolved and recorded before the truth lock.

### Tier C — deployment truth, 25 cases

Adds:

- workload/deployment identity;
- repository-declared deployed authority;
- required authority where defensible;
- missing/excess/mixed/aligned/unresolved classification where defensible;
- conditional/inherited/custom authority;
- evidence provenance;
- explicit `runtime_effectiveness: not_verified`.

Two reviews are required before execution.

## Assertions rather than vague labels

Security truth is stored as atomic assertions. Examples:

```text
agent root_agent can_invoke tool send_message
agent root_agent delegates_to agent researcher
agent root_agent reaches_mcp_tool slack/send_message
tool shell has_capability process.execute
tool publish requires_approval true
path AP-017 is_valid true
identity service-account-X bound_to workload-Y
```

Every assertion has:

- a stable assertion ID;
- subject;
- predicate;
- object/value;
- expected state: `present`, `absent` or `unresolved`;
- source evidence;
- rationale;
- review state.

This makes false-positive and false-negative analysis explicit.

## Primary research questions

### RQ1 — Entity discovery

How accurately does HorusTrace identify agent roots, tools, MCP servers and explicit delegation edges?

Primary metrics:

- precision;
- recall;
- F1;
- per-framework precision/recall;
- previously unseen vs previously studied repositories.

### RQ2 — Effective authority

Can HorusTrace reconstruct which effective agent can invoke which tools/MCP capabilities, including bounded delegated paths?

Primary metrics on Tier B:

- relationship precision;
- relationship recall;
- delegated-path precision/recall;
- MCP binding precision/recall;
- approval-state accuracy;
- identity attribution accuracy where truth is available.

### RQ3 — Security findings

Are HorusTrace findings materially correct and appropriately scoped?

Metrics:

- assertion-level finding precision/recall;
- severity disagreement;
- source-context disagreement;
- false-positive taxonomy;
- false-negative taxonomy.

Headline finding counts are not accuracy metrics.

### RQ4 — Attack paths

Are reported end-to-end attack paths structurally valid?

Tier B measures:

- path precision against independently adjudicated valid/invalid paths;
- recall against pre-adjudicated known paths;
- incorrect reachability edge contribution;
- incorrect source/sink classification;
- approval/control handling;
- unknown-path handling.

### RQ5 — Conservative uncertainty

Does HorusTrace avoid unsupported certainty when evidence is dynamic, incomplete or unsupported?

Metrics:

- correct unresolved rate;
- unsupported-certainty rate;
- unresolved-reason accuracy;
- percentage of errors caused by framework gaps vs evidence limits.

A correct `unresolved` is a successful outcome.

### RQ6 — Deployment authority

On Tier C, how accurately can HorusTrace bind workloads/identities and reason about repository-declared least privilege?

Report separately:

- workload identity precision/recall;
- deployed-authority reconstruction;
- required-authority recall;
- missing-authority precision/recall;
- excess-authority precision/recall;
- mixed/aligned classification;
- correct unresolved rate;
- provider-specific coverage.

No live-cloud claim is permitted unless separately verified outside this study.

### RQ7 — Generalization

How much performance differs by:

- framework;
- single-agent vs multi-agent;
- MCP vs non-MCP;
- previously studied vs previously unseen repositories;
- runtime source vs examples/templates;
- provider/deployment environment.

Aggregate results must never be reported without per-stratum results.

## Pre-registered product thresholds

These are product-readiness thresholds, not repository-selection rules. Missing a threshold is a study result, not a reason to alter the cohort.

| Metric | Threshold |
| --- | ---: |
| Agent-root precision | >= 0.95 |
| Agent-root recall | >= 0.90 |
| Tool/MCP/delegation edge precision | >= 0.90 |
| Tool/MCP/delegation edge recall | >= 0.85 |
| Effective-authority relationship precision | >= 0.90 |
| Effective-authority relationship recall | >= 0.80 |
| Attack-path precision | >= 0.80 |
| Unsupported-certainty rate | <= 0.05 |
| Deployment workload-identity precision | >= 0.95 |
| Deployment workload-identity recall | >= 0.90 |

Finding and IAM least-privilege metrics are reported without a pass/fail threshold in the first major study because rule/provider coverage is intentionally incomplete. Their distributions and error taxonomies determine future thresholds.

## Error taxonomy

Every mismatch must be assigned at least one cause.

Initial categories:

- framework_root_discovery;
- tool_discovery;
- mcp_discovery;
- mcp_binding;
- delegation_resolution;
- callback_or_helper_resolution;
- approval_semantics;
- identity_resolution;
- capability_mapping;
- resource_resolution;
- destination_resolution;
- source_context;
- attack_path_reachability;
- attack_path_source_sink;
- policy_semantics;
- deployment_identity;
- required_authority;
- deployed_authority;
- authority_completeness;
- unsupported_framework_or_provider;
- dynamic_runtime_evidence;
- human_ground_truth_error;
- study_harness_error;
- other.

New categories may be added after execution, but existing mismatches must not be silently reclassified to improve headline metrics.

## Disagreement protocol

The frozen truth is never overwritten because HorusTrace disagrees.

After baseline execution:

1. record the mismatch;
2. secondary adjudicator reviews the pinned source without being told that HorusTrace is presumed correct;
3. classify the disagreement as scanner error, ground-truth error, ambiguous evidence, harness error or unresolved;
4. preserve the original locked truth;
5. record any correction as a separate adjudication note;
6. report metrics both against original pre-run truth and, separately, against post-hoc adjudicated truth.

This preserves the same discipline that exposed the previous `natural-008` human omission.

## Feature freeze

Until the baseline report is immutable, production changes are prohibited except:

- HorusTrace security vulnerability fixes;
- nondeterminism fixes;
- scanner crashes that prevent study execution;
- study-harness defects;
- repository-fetch/reproducibility fixes.

If an allowed production fix occurs:

- retain the original result;
- record the exact old/new HorusTrace SHAs;
- rerun the same frozen cases;
- never replace the baseline artifact.

Feature requests discovered by the study go into the post-study roadmap, not into the baseline scanner.

## Safety and reproducibility

The study:

- pins every target to an exact commit SHA;
- does not install/import/execute target applications;
- does not launch target agents or MCP servers;
- does not use target credentials;
- does not call production cloud/SaaS APIs;
- uses static repository evidence;
- treats repository IaC as declared intent, not live deployment state;
- records clone, parse, timeout and scanner failures separately from semantic mismatches;
- retains `runtime_effectiveness: not_verified` for static evidence.

## Reporting

The baseline report must include:

- exact HorusTrace SHA;
- exact cohort manifest digest;
- all target SHAs;
- execution failures/timeouts;
- structural precision/recall;
- effective-authority metrics;
- attack-path metrics;
- finding assertion metrics;
- unresolved/unsupported-certainty metrics;
- deployment metrics;
- per-framework breakdowns;
- previously unseen breakdown;
- false-positive taxonomy;
- false-negative taxonomy;
- ground-truth disagreements;
- study limitations.

No result may be summarized only as a count of agents, tools or findings.

## Study phases

1. **Protocol freeze** — land this methodology, machine-readable protocol and validators.
2. **Candidate discovery** — build a pool materially larger than 180 without HorusTrace execution.
3. **Candidate screening** — document every inclusion/exclusion decision.
4. **Cohort freeze** — select 180 exact-SHA repositories and pre-select Tier B/Tier C subsets.
5. **Ground truth** — complete and lock Tier A; dual-review Tier B/Tier C.
6. **Baseline execution** — run frozen HorusTrace SHA without feature changes.
7. **Disagreement adjudication** — preserve original truth and add separate notes.
8. **Error analysis** — quantify root causes and framework/provider gaps.
9. **Roadmap derivation** — rank future work by frequency, security impact and tractable engineering effort.
10. **Post-fix validation** — only after roadmap decisions, rerun the identical frozen cohort.

## Immediate next action after protocol merge

Candidate discovery begins only after this protocol is merged. The first discovery phase should collect at least **300 candidate repositories** so the final 180 are not selected from a narrow or convenience sample.
