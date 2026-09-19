# Reviewed benchmark corpus

Each case represents a small but coherent agent security boundary. Its expected
`RULE@agent` set is manually reviewed and exact: additional findings count as false
positives and missing findings count as false negatives.

The v0.2 corpus contains 26 reviewed scenarios across secure agents, execution,
delegation, MCP, identity, data/network reachability, attack paths,
dynamic/unresolved configuration, and false-positive traps. One case intentionally
expects incomplete static analysis and an exact `ARG-COV-*` diagnostic; every other
case fails if coverage is incomplete.

The corpus has an `.agentreachguard-ignore` marker, so intentionally vulnerable
fixtures do not affect scans started at the repository root. Scanning an individual
case still works because its scan root is below the marker. Run the corpus explicitly:

```bash
agentreachguard benchmark benchmarks/cases.yaml
```

Add a case only with a documented trust boundary and reviewed expectations. Update
an expectation when scanner behavior is intentionally changed; the diff should
explain why the old expectation was wrong or the rule semantics changed. Do not add
renamed copies of an existing fixture merely to increase the case count.

Benchmark JSON includes aggregate and per-rule true-positive, false-positive, and
false-negative metrics. Precision and recall are `null` when their denominator is
zero. `history/v0.2.0.json` is the release-candidate snapshot generated from the
reviewed corpus; normal benchmark runs never rewrite it.
