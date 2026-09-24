# MCP Unresolved-Reference Taxonomy v1

HorusTrace distinguishes **binding uncertainty** from **authority uncertainty**.

A bound MCP relationship can still have unresolved authority dimensions—for example an
unknown tool catalogue. That remains part of Effective MCP Authority.

This taxonomy is only for cases where HorusTrace cannot establish a unique static MCP
binding, or where a concrete MCP declaration is present but not bound to an agent.

## Compatibility model

Two counts are intentionally separate:

- `unbound_servers` / coverage `mcp.unbound` — concrete MCP server declarations that
  are not bound to an agent. This preserves the existing inventory semantics.
- `unresolved_references` — the broader set of unresolved observations, including both
  concrete unbound declarations and unresolved agent references.

Unresolved agent references are **not** inserted into `Graph.all_mcp_servers()`. They
therefore do not inflate concrete server counts or trigger server findings as if a server
declaration existed.

## Reason taxonomy

### Resolvable/static

- `server_not_declared` — an explicit agent reference has no matching static declaration.
- `declaration_not_agent_bound` — a concrete server declaration exists but no agent
  binding is evidenced.
- `cross_file_reference_unlinked` — a same-name repository declaration exists, but the
  imported reference does not uniquely link to it.
- `name_mismatch` — reserved for explicit name mismatch evidence.
- `scope_reference_unmatched` — reserved for statically unmatched scope references.

### Evidence-limited

- `dynamic_server_selection` — the agent's server reference is runtime-computed.
- `dynamic_tool_filter` — reserved for unresolved binding shapes involving dynamic filters.
- `catalogue_unknown` — reserved for binding resolution that depends on an unknown catalogue.
- `external_configuration` — repository-local evidence needed for the binding is absent.
- `framework_semantics_unknown` — a reference is observed but generic framework binding
  semantics are not known.
- `ambiguous_multiple_candidates` — more than one static declaration could satisfy the
  reference.
- `unsupported_reference_shape` — the syntactic reference cannot be normalized safely.

Not every reserved reason is necessarily emitted by current adapters. The v1 vocabulary
is versioned so future adapters can use the same stable reason codes rather than inventing
free-form strings.

## Record shape

Each unresolved observation includes:

```json
{
  "reference_id": "mcp-unresolved-v1:...",
  "reference_kind": "agent_reference",
  "agent": "worker",
  "framework": "fast-agent",
  "server": "shared",
  "reason": "ambiguous_multiple_candidates",
  "resolution_class": "evidence_limited",
  "candidate_declarations": [],
  "evidence_gaps": ["unique_server_binding"],
  "recommendation": "Disambiguate the reference ...",
  "runtime_effectiveness": "not_verified"
}
```

Reference IDs intentionally exclude destination values and source locations. URLs can
contain credentials or query material, and checkout paths / line movement should not
change stable identity.

## Imported-reference safety

Repository import references are bound only when exactly one declaration matches the
server name **and** imported module.

If resolution fails, the placeholder is removed from the agent's effective MCP inventory
and retained as an unresolved reference. It is never later rewritten to
`context_binding=bound` merely because it originated inside an agent declaration.

This preserves the v0.6 invariant:

> unknown is neither bound nor allowed.

## FastAgent

For static `servers=[...]` references:

- one matching scoped declaration → bound
- zero declarations → `server_not_declared`
- multiple candidates → `ambiguous_multiple_candidates`

Dynamic server collections remain `dynamic_server_selection`.

Concrete candidate declarations remain in the unbound-server inventory until a unique
binding is established.

## Reporting

Effective MCP Authority schema v2 exposes:

- `unbound_servers`
- `unresolved_references`
- `unresolved_agent_references`
- `unbound_by_reason` — concrete declarations only
- `unresolved_by_reason` — all unresolved observations
- `unresolved_by_resolution_class`

The scanner coverage resolution block exposes the same distinction, allowing frozen
cohort studies to compare the historical concrete-unbound baseline separately from new
reference-resolution quality.
