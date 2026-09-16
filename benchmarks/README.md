# Reviewed benchmark corpus

Each case represents a small but coherent agent security boundary. Its expected
`RULE@agent` set is manually reviewed and exact: additional findings count as false
positives and missing findings count as false negatives. Coverage gaps fail a case.

The corpus has an `.agentreachguard-ignore` marker, so intentionally vulnerable
fixtures do not affect scans started at the repository root. Scanning an individual
case still works because its scan root is below the marker. Run the corpus explicitly:

```bash
agentreachguard benchmark benchmarks/cases.yaml
```

Add a case only with a documented trust boundary and reviewed expectations. Update
an expectation when scanner behavior is intentionally changed; the diff should
explain why the old expectation was wrong or the rule semantics changed.
