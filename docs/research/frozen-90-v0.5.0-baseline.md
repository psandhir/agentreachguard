# Frozen 90 v0.5.0 validation baseline

This document records the public-corpus validation baseline used for the HorusTrace
v0.5.0 release.

## Scanner

Release-candidate lineage: integrated v0.5 main including Agent Security Graph v1,
Authority Delta v1, inbound entrypoint provenance, adapter contract v1, and the
entrypoint-diversity fix.

The validation used the existing frozen 90-repository manifests. Repository revisions
were not moved to improve results.

## Aggregate results

| Metric | Value |
| --- | ---: |
| Repositories requested/scanned | 90 / 90 |
| Scanner errors | 0 |
| Scanner timeouts | 0 |
| Agents | 2,076 |
| Tools | 3,413 |
| MCP servers | 633 |
| Identities | 78 |
| Flow paths | 140 |
| Proven agent-reachable flows | 6 |
| Proven non-agent flows | 133 |
| Unknown agent reachability | 1 |
| Attack paths | 25 |
| Static-dataflow-backed attack paths | 2 |
| ADG nodes | 6,690 |
| ADG edges | 5,630 |
| Bound MCP references | 117 |
| Unbound MCP references | 516 |
| MCP agent invokes | 117 |
| MCP identity edges | 3 |
| Findings | 1,105 |

## Reachability by cohort

| Cohort | Proven agent-reachable | Proven non-agent | Unknown |
| --- | ---: | ---: | ---: |
| A | 2 | 118 | 1 |
| B | 4 | 2 | 0 |
| C | 0 | 13 | 0 |
| **Total** | **6** | **133** | **1** |

## Residual unknown

The sole remaining unknown flow is in `ArcadeAI/arcade-mcp`:

- source: `httpx.get`
- sink: `httpx.post`
- pair: `external_http_response -> external_send`
- flow chain: `get_valid_access_token -> refresh_access_token`
- execution context: runtime
- reachability basis: `no_agent_tool_binding_evidence`

The auth-token utility is shared by both CLI code and MCP-server runtime. Inbound
provenance recovers the server path:

```text
MCPServer.__init__
→ _init_arcade_client
→ _load_config_values
→ get_valid_access_token
```

The analysis remains bounded and can report truncation when more inbound roots exist
than the emitted evidence budget.

This residual is intentionally preserved as unknown because static evidence does not
justify forcing either an agent-reachable or proven-non-agent conclusion.

## Interpretation

The progression of residual unknown flow reachability during the frozen study was:

```text
32 → 5 → 1
```

The reductions came from general semantic corrections, including subprocess payload
versus executable-control modeling and execution-context proof. They were not produced
by repository-specific suppression or by reclassifying uncertain runtime behavior as
safe.

The remaining unknown is therefore treated as evidence that HorusTrace preserves
ambiguity when the repository genuinely supports multiple runtime consumers.
