# Trust Boundary Classification v1

Trust Boundary Classification v1 gives HorusTrace a versioned vocabulary for describing
the security boundary represented by an Effective Authority Relationship v1.

It is descriptive, evidence-backed, and static-only. It does not assign a numeric risk
score and does not claim runtime exploitability.

## Boundary families

### Mutation

Supported classes are:

- `no_mutation`
- `local_session_mutation`
- `internal_mutation_unspecified`
- `persistent_internal_mutation`
- `external_side_effect`
- `destructive_mutation`
- `security_identity_sensitive_mutation`
- `unknown`

`process.execute`, computer-control authority, and generic MCP authority are **not**
classified as no-mutation merely because a normalized write capability is absent.
Their mutation effect remains `unknown` unless stronger evidence is available.

The current name-derived sensitive-write hint is not sufficient to promote a relationship
to a financial-sensitive boundary. HorusTrace will only make that distinction when a
future normalized evidence source can establish the domain without relying on tool names.

### Network

Supported classes are:

- `no_external_network`
- `fixed_destination`
- `provider_constrained_destination`
- `internet_retrieval`
- `arbitrary_egress`
- `unknown`

A specific resolved MCP URL is a fixed destination. A generic external-network capability
without destination or normalized network-scope evidence remains unknown.

### Identity

Supported classes are:

- `workload_service_identity`
- `oauth_delegated_authority`
- `iam_authority`
- `broad_privileged_authority`
- `unknown`

Broad/admin roles, wildcard permissions, and known broad OAuth scopes support the broad
privileged class. Missing identity evidence remains unknown rather than being interpreted
as no identity.

### Control

Supported classes are:

- `mandatory_approval`
- `guardrail_control`
- `explicitly_no_approval`
- `unknown`

An unspecified approval state is not equivalent to approval. A generic guardrail is kept
distinct from explicit mandatory approval.

### MCP tool scope

Supported classes are:

- `explicit_allowlist`
- `denylist_only`
- `dynamic_scope`
- `unknown`
- `not_applicable`

Dynamic filters remain partial evidence. An unresolved or unrestricted/unknown catalogue
is not treated as equivalent to a denylist.

## Boundary crossings

Two versions of the same stable authority relationship can be compared with
`classify_boundary_crossings()`.

Examples of supported crossings include:

```text
mutation:
  local_session_mutation -> external_side_effect
  direction: expanded

network:
  fixed_destination -> arbitrary_egress
  direction: expanded

identity:
  workload_service_identity -> broad_privileged_authority
  direction: expanded

control:
  mandatory_approval -> explicitly_no_approval
  direction: weakened

mcp_scope:
  explicit_allowlist -> denylist_only
  direction: expanded
```

Crossings are emitted only where the taxonomy has a supported ordering. If either side
is unknown, HorusTrace does not manufacture an escalation. Dynamic MCP scope is likewise
not ranked against an explicit allowlist unless effective scope can be resolved.

## Relationship to Authority Contract

Authority Contract answers whether observed authority is permitted.

Trust Boundary Classification answers what kind of authority the relationship represents,
and what security boundary changed between two revisions.

The next v0.6 integration layer can therefore combine:

```text
Authority Delta
  + Trust Boundary Crossing
  + Authority Contract result
```

without collapsing these separate concepts into a single opaque risk score.
