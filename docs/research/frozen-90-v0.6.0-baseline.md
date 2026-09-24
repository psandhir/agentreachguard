# Frozen 90 v0.6.0 validation baseline

This document records the frozen public-corpus validation used to assess the HorusTrace
v0.6 authority-policy release line.

- Frozen target corpus: **2026-09-22**
- Validation date: **2026-09-24**
- v0.6 validation harness commit: `bee59738dd8ea4778a8dd0ea74039304dc307a78`
- Product lineage under test: main after PR #103, merge commit
  `dbb06f6531c4343db6cb6ce087db27cc52c2e550`
- Frozen-90 workflow run: **36036585304**
- Exact v0.5 final comparison run: **36023300135**

Target repository revisions were not moved. Repositories were fetched at their existing
frozen SHAs and were not imported, installed, or executed.

## Release comparison

The strongest result is simple: **every legacy v0.5 release metric compared here has
delta 0 on v0.6**.

| Metric | v0.5.0 | v0.6 validation | Delta |
| --- | ---: | ---: | ---: |
| Repositories scanned | 90 / 90 | 90 / 90 | 0 |
| Scanner errors | 0 | 0 | 0 |
| Scanner timeouts | 0 | 0 | 0 |
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

This is important because v0.6 adds policy evaluation, trust-boundary classification,
policy-aware PR gating, explainability, and a richer MCP resolution model without moving
the established static-analysis baseline.

## Reachability remains conservative

The frozen reachability split remains:

| Cohort | Agent-reachable | Proven non-agent | Unknown |
| --- | ---: | ---: | ---: |
| A | 2 | 118 | 1 |
| B | 4 | 2 | 0 |
| C | 0 | 13 | 0 |
| **Total** | **6** | **133** | **1** |

The sole residual unknown remains the previously adjudicated `ArcadeAI/arcade-mcp`
flow. v0.6 did not force that ambiguity into either a reachable or non-agent conclusion.

## MCP resolution: inventory versus references

The historical **516** figure is a count of concrete MCP server declarations that are
not bound to an agent. v0.6 preserves that number exactly.

The new unresolved-reference taxonomy exposes a second class of evidence that was
previously hidden:

- concrete unbound declarations: **516**
- unresolved agent references: **15**
- total unresolved observations: **531**

These numbers must not be compared as though 516 grew to 531. The additional 15 are
newly visible references, not newly discovered server declarations.

### Reasons

| Reason | Count | Interpretation |
| --- | ---: | --- |
| `declaration_not_agent_bound` | 516 | Existing concrete declaration has no evidenced agent binding |
| `server_not_declared` | 13 | Agent names a server with no matching static declaration |
| `ambiguous_multiple_candidates` | 1 | Multiple candidates exist and no unique static choice is justified |
| `dynamic_server_selection` | 1 | Server selection is runtime-computed |

Resolution classes:

- `resolvable_static`: **529**
- `evidence_limited`: **2**

Only two repositories contribute unresolved agent references:
`evalstate/fast-agent` (10) and `Klavis-AI/klavis` (5).

### Manual adjudication

For frozen `Klavis-AI/klavis`, the five references are:

- `anon_hf`
- `test_hf`
- `test_all_hf`
- `live_hf`
- `skybridge`

Each has zero candidate declarations at the pinned SHA. The repository contains the
FastAgent references in Hugging Face E2E examples but no repository-local
`fast-agent.yaml` / `fast-agent.yml` that declares those names.

For frozen `evalstate/fast-agent`:

- eight test/manual references have no matching static declaration;
- one documentation reference to `filesystem` has **11 same-name candidate
  declarations** across separate example configurations and no unique scoped choice;
- one `huggingface` reference uses runtime-computed server selection.

The ambiguous reference is therefore correctly preserved rather than guessed. The
dynamic reference is genuine evidence-limited behavior.

Manual review found **no false-bound case and no generic resolver defect** among the
15 newly surfaced references.

## Trust Boundary Classification empirical coverage

v0.6 classified **2,600 effective-authority relationships**.

### Mutation

| Class | Relationships |
| --- | ---: |
| `no_mutation` | 1,133 |
| `local_session_mutation` | 9 |
| `internal_mutation_unspecified` | 211 |
| `persistent_internal_mutation` | 6 |
| `external_side_effect` | 55 |
| `destructive_mutation` | 3 |
| `security_identity_sensitive_mutation` | 3 |
| `unknown` | 1,180 |

### Network

| Class | Relationships |
| --- | ---: |
| `no_external_network` | 2,288 |
| `fixed_destination` | 16 |
| `provider_constrained_destination` | 108 |
| `internet_retrieval` | 135 |
| `arbitrary_egress` | 53 |

Network classification has **0 unknown relationships** in this cohort.

### Identity

- `workload_service_identity`: **8**
- `unknown`: **2,592**

Identity authority is therefore the largest empirical evidence gap: about 99.7% of
relationships lack enough normalized identity evidence for a stronger static class.

### Control

- `mandatory_approval`: **83**
- `guardrail_control`: **87**
- `explicitly_no_approval`: **2**
- `unknown`: **2,428**

Control state is also sparse: about 93.4% remains unknown.

### MCP tool scope

Of 117 bound MCP relationships:

- explicit positive allowlist: **8**
- unknown scope: **109**

The other 2,483 effective-authority relationships are non-MCP and therefore
`not_applicable`.

This is not a release failure. It is an honest statement about the static evidence
available in today's public corpus and identifies where future normalization work has
the highest leverage.

## Authority Contract corpus limitation

The frozen 90 repositories contain **zero repository-local v0.6 Authority Contract
policies**.

Consequently the corpus has:

- agents with Authority Contract: **0**
- contract relationships evaluated: **0**
- violations: **0**
- unresolved contract assessments: **0**

This must **not** be interpreted as “all 90 repositories are compliant.” It means the
public corpus does not contain HorusTrace's new policy input.

Authority Contract parsing, evaluation, stable violation identity, Explainability v2,
base/head policy delta, and policy-gate behavior are validated by the project regression
suite and CI fixtures rather than by this observational public corpus.

## Release interpretation

The frozen study supports four conclusions:

1. **No legacy scanner regression was observed.** Every compared v0.5 metric is
   unchanged.
2. **Unknown was not optimized away.** The sole flow-reachability unknown remains
   unknown, and unresolved MCP bindings are surfaced separately instead of being guessed.
3. **The MCP taxonomy improves visibility without inventory distortion.** The historical
   516 concrete-unbound baseline remains 516 while 15 previously hidden agent references
   become explainable.
4. **v0.6 exposes real evidence gaps.** Identity, control, and MCP positive-scope evidence
   are sparse in the frozen corpus; these should be treated as future coverage work, not
   silently inferred authority.

All runtime-effectiveness claims remain `not_verified`.
