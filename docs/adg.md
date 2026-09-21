# Agent Dependency Graph (ADG)

HorusTrace v0.4 introduces a versioned, framework-agnostic Agent Dependency
Graph (ADG). The ADG is a deterministic static representation of the agent security
surface; it does not execute the target or claim runtime authorization.

## Node types

ADG v1 can represent agents, tools, MCP servers, models, prompts, inputs, memory,
identities, data resources, network destinations, policy controls, and static flow
steps. Prompt nodes store a digest and length rather than prompt contents.

## Edge types

The relationship vocabulary includes `INVOKES`, `DELEGATES_TO`,
`RECEIVES_INPUT_FROM`, `READS_FROM`, `WRITES_TO`, `USES_IDENTITY`,
`USES_MODEL`, `USES_PROMPT`, `CONNECTS_TO`, `READS_MEMORY`,
`WRITES_MEMORY`, `GUARDED_BY`, `CONTROL_FLOWS_TO`, `DATA_FLOWS_TO`, and
`CAN_REACH_AUTHORITY`.

The graph separates three security dimensions:

- **Data flow** — where supported values can move.
- **Control flow** — which graph or agent components can invoke or hand off to others.
- **Authority flow** — which identities and delegated capabilities become reachable.

## Export

```bash
horustrace graph . --output adg.json
```

Node and edge IDs are stable for the same repository-relative source location and
semantic identity. Graph output is sorted deterministically and exposes a canonical
digest.

## Static data-flow scope

v0.4 performs bounded source-to-sink analysis over a supported Python subset. The
initial engine follows direct assignments, common expressions, simple branch merges,
and resolved local/imported helper functions. It recognizes a conservative set of
untrusted or sensitive sources and high-impact sinks such as process execution,
outbound writes, and memory/checkpoint writes.

A path with `basis: static_dataflow` means HorusTrace established a static
value dependency through supported constructs. It does **not** mean the path has been
exploited, that runtime policy is ineffective, or that arbitrary Python semantics
were fully resolved.

When tainted data crosses an unresolved helper, HorusTrace retains explicit
coverage uncertainty rather than upgrading that path to supported confidence.

## AIBOM

```bash
horustrace aibom . --output agent-aibom.json
```

The Agent Bill of Materials inventories discovered agents, models, prompt digests,
tools, MCP servers, memory, identities, resources, destinations, and policy controls.
It is generated from the ADG so framework-specific adapters share a common inventory
format.
