# Explainability v2

Explainability v2 connects repository-local Authority Contract intent to the static
evidence HorusTrace used to reconstruct effective authority.

It is designed to answer:

> Which policy clause was violated, by which effective authority relationship, using
> which identity/control/resource/destination evidence, and where did both sides come
> from?

## Source-addressable contract clauses

Authority Contract v1 retains source locations for each supported clause:

- `allow.<dimension>`
- `deny.<dimension>`
- `require_approval_for`
- `mcp_tools.<server>.allow`
- `mcp_tools.<server>.deny`

The location is the YAML value node for that clause. If an exact location is unavailable
—for example, when a contract is constructed programmatically—HorusTrace falls back to
the Authority Contract block location.

No manifest syntax changes are required.

## Structured explanation

Every Authority Contract violation and unresolved assessment includes an
`explanation` object.

Example shape:

```json
{
  "policy": {
    "clause": "deny.capabilities",
    "dimension": "capabilities",
    "location": {
      "path": "horustrace.manifest.yaml",
      "line": 12,
      "column": 25
    },
    "expected": ["process.execute"]
  },
  "authority": {
    "relationship_id": "authority-v1:...",
    "agent": "support",
    "target": {
      "kind": "tool",
      "name": "shell"
    },
    "resolution": "partially_resolved",
    "dimensions": {
      "approval": "resolved",
      "capabilities": "resolved"
    },
    "observed": ["process.execute"]
  },
  "identity": null,
  "control": {
    "required": false,
    "guardrails": false
  },
  "resources": [],
  "destinations": [],
  "mcp_tool_scope": null,
  "source_evidence": [],
  "unresolved_dimensions": ["identity", "resources", "destinations"],
  "runtime_effectiveness": "not_verified"
}
```

The actual explanation may contain additional resolved relationship dimensions. Values
are structured evidence already present in the normalized authority model; HorusTrace
does not copy source-file contents into the explanation.

## Stable identifiers and sensitive evidence

Explainability data does **not** participate in stable violation fingerprints.

A violation ID is still derived only from:

- status
- stable authority relationship ID
- contract clause
- violation reason

Observed principals, destinations, policy values, credentials, tokens, source paths and
other evidence do not become fingerprint inputs.

This keeps historical-baseline behavior stable while avoiding accidental hashing of
sensitive evidence.

## Diff reporting

Authority-policy delta records preserve the explanation object while normalizing nested
source paths relative to each checked-out Git revision.

Console and Markdown diff output show:

- contract clause
- violation reason
- expected / observed values
- policy source location
- authority source location

JSON retains the full structured explanation for automation and downstream tooling.

## Evidence limits

Explainability v2 remains static analysis. A complete explanation means HorusTrace can
explain the static evidence chain it reconstructed; it does not prove that the authority
was exercised at runtime.

`runtime_effectiveness` therefore remains `not_verified`.
