# HorusTrace Product Roadmap Derived from the 2026 Real-World Study

This roadmap is ordered by measured study impact. The ordering intentionally favors **graph fidelity and recall** over new policy rules.

## P0 — Cross-framework discovery and authority foundation

### 1. LangGraph semantic adapter v2

**Measured reason:** LangGraph accounts for 252/346 missed agent/workflow entities and has tool recall 0.068.

Build a first-class LangGraph semantic model covering:

- `StateGraph.add_node` / compiled graph construction;
- functions, callables, runnable objects and classes registered as nodes;
- `ToolNode`, `tools_condition`, and LangChain `@tool` integration;
- `create_react_agent` and prebuilt agent executors;
- subgraphs and supervisor/router patterns;
- notebook (`.ipynb`) source cells;
- distinction among model-driven agent nodes, tool nodes, deterministic transforms and control nodes.

**Acceptance gate:** frozen-cohort LangGraph agent recall ≥0.80 and tool recall ≥0.70 without reducing completeness-case precision below 0.90.

### 2. Framework-neutral agent/tool-loop discovery

**Measured reason:** MCP/custom agent recall is 0.063; tool recall is 0.000. This stratum contributes 408/814 missed tools.

Introduce a framework-neutral intermediate representation for:

`model/LLM call → advertised tool schema/registry → model-selected tool call → dispatcher → concrete callable/MCP call`.

Recognize:

- dictionaries/lists of tool functions;
- JSON/function-schema registries;
- generic OpenAI-compatible tool calling;
- `list_tools` / `call_tool` MCP client loops;
- custom routers/dispatch tables;
- remote/SSE/stdio MCP session construction;
- tool execution hidden behind helper classes.

**Acceptance gate:** MCP/custom root recall ≥0.60 and tool recall ≥0.60 on the unchanged cohort, with conservative unresolved output for ambiguous loops.

### 3. MCP discovery and binding v2

**Measured reason:** 6/22 explicit servers matched; recall 0.273.

Support MCP declarations from:

- constructor lists and object attributes;
- late initialization;
- config files and environment-driven command/URL definitions;
- remote HTTP/SSE, stdio and framework wrappers;
- Pydantic AI `mcp_servers=`;
- OpenAI hosted/local MCP tools;
- generic MCP client sessions;
- server aliases and tool filters.

Every MCP server/tool binding should carry provenance and an explicit confidence/resolution state.

**Acceptance gate:** explicit MCP-server recall ≥0.85 on the frozen cohort and no unsupported full-resolution claims for dynamic server lists.

### 4. Provenance-aware effective-authority binding

**Measured reason:** effective-authority precision 0.278 / recall 0.611. LangGraph alone contributes 50 measured false positives on completeness-marked cases.

Replace broad co-location/graph-proximity inference with evidence-ranked binding:

- direct registration;
- agent constructor binding;
- ToolNode membership;
- explicit handoff/agent-as-tool relationship;
- MCP filter/server membership;
- shared registry with proven lookup key;
- unresolved when only module-level co-presence exists.

Add a relationship provenance trace to every effective-authority edge so false positives are diagnosable.

**Acceptance gate:** effective-authority precision ≥0.80 and recall ≥0.75 on the identical Tier-B cohort before considering new authority policy rules.

## P1 — Reliability and deployment evidence

### 5. OpenAI Agents and Pydantic AI indirect registration coverage

Focus on:

- `agent.tool(...)`, decorators and toolsets;
- agent-as-tool;
- handoffs and dynamically assembled agents;
- hosted tools;
- MCP constructor/configuration lists;
- helper-generated tool arrays.

**Acceptance gate:** OpenAI tool recall ≥0.70; Pydantic AI tool recall ≥0.75; MCP-positive cases no longer collapse to zero detection.

### 6. Deployment identity reconstruction across GCP/AWS/Azure/Kubernetes

**Measured reason:** 0/7 source-declared identities matched in four Tier-C cases.

Build provider-neutral identity evidence first:

- service-account / managed-identity / IAM-role / Kubernetes service-account declarations;
- workload-to-identity bindings;
- deployment manifests and IaC modules;
- provenance from application → deployable workload → identity → authority.

Then add provider-specific authority semantics.

**Acceptance gate:** identity recall ≥0.90 on the frozen Tier-C subset plus a new independently selected deployment validation set; keep runtime effectiveness explicitly unverified.

### 7. Filesystem traversal hardening

Catch `PermissionError`, broken symlinks and other stat/read failures. Emit a coverage diagnostic containing path and reason, continue the scan, and ensure security-graph generation survives.

**Acceptance gate:** 180/180 frozen cases complete without scanner crash.

### 8. Human-adjudicated attack-path benchmark

Create 20–30 Tier-B path cases containing:

- valid end-to-end paths;
- invalid near-misses;
- approval-gated paths;
- delegated paths;
- MCP-filtered paths;
- dynamic/unresolved cases.

Lock two independent human reviews before rerunning HorusTrace.

**Acceptance gate:** establish actual attack-path precision/recall; do not market a quantitative attack-path accuracy claim before this exists.

## P2 — Finding quality and UX

### 9. Finding semantic adjudication

Sample findings stratified by rule and severity from the 268 baseline findings. Human-adjudicate whether the rule, source, sink, authority scope and severity are correct.

Use the result to:

- tune noisy rules;
- attach stronger provenance;
- distinguish “supported”, “potential” and “unknown”;
- set the first finding-precision threshold.

### 10. Coverage certificates as a first-class output

94/179 successful cases were analysis-incomplete. Make coverage understandable at the framework/capability level:

- agent discovery completeness;
- tool discovery completeness;
- MCP completeness;
- authority-binding completeness;
- deployment-identity completeness.

A user should be able to tell whether “no finding” means “no problem observed” or “insufficient evidence.”

## Release sequence

### v0.9 — Recall foundation
LangGraph v2 + framework-neutral loops + MCP discovery/binding + traversal hardening.

### v0.10 — Authority fidelity
Provenance-aware authority binding + OpenAI/Pydantic indirect registration + completeness certificates.

### v0.11 — Deployment and validation
Provider-neutral deployment identity model + GCP/AWS/Azure/Kubernetes adapters + human path/finding validation packs.

## Mandatory validation rule

Every P0/P1 change must be evaluated against the **same frozen 180-case cohort and locked truth**. Preserve the original `418db4e29798a7d25df686dd7bccfd9fefa225bd` baseline and publish deltas; never replace the baseline artifact.
