# Authority Contract v1

Authority Contract v1 is the v0.6 repository-local policy model for constraining an
agent's effective authority.

It extends the existing `horustrace.manifest.yaml` agent policy. Existing v0.5 policy
fields remain valid and retain their current semantics.

## Manifest syntax

```yaml
version: 1
agents:
  - name: support-agent
    policy:
      authority:
        allow:
          capabilities:
            - data.read
            - external.write
          identities:
            - support-bot
          resources:
            - tickets/*
          destinations:
            - https://support.example.test
          iam_roles:
            - roles/viewer
          permissions:
            - tickets.read
          oauth_scopes:
            - issues:read
          mcp_servers:
            - github

        deny:
          capabilities:
            - process.execute
            - destructive.write
          iam_roles:
            - roles/owner
          mcp_servers:
            - filesystem

        require_approval_for:
          - external.write

        mcp_tools:
          - server: github
            allow:
              - issues_read
              - issues_update
            deny:
              - repo_delete
```

## Normalized dimensions

The contract separates authority into framework-neutral dimensions:

- capabilities;
- identities;
- resources;
- destinations;
- IAM roles;
- permissions;
- OAuth scopes;
- MCP servers;
- per-server MCP tool scope;
- capabilities that require explicit approval.

String-or-list syntax is accepted for leaf sets. Normalization removes ordering as a
security semantic and emits deterministic sorted values.

## Safety semantics

Authority Contract v1 is static and local-first.

The contract does not make unresolved authority safe. Missing identity, destination,
resource, approval, IAM, OAuth or MCP evidence remains unresolved until the effective
authority evaluator has enough supported evidence to assess the clause.

Unknown fields, invalid nested shapes and non-string authority values fail the manifest
closed rather than being ignored.

## Compatibility

The existing policy fields remain supported:

```yaml
policy:
  required: [data.read]
  deny: [process.execute]
  allowed_resources: [records/*]
  allowed_destinations: [api.example.test]
  require_approval_for: [data.write]
  max_privileged_capabilities: 2
```

Authority Contract v1 is additive to these fields. Evaluation of the new contract
against Effective Authority Relationship v1 is implemented separately so schema
parsing does not silently change legacy finding behavior.


## Evaluation semantics

Authority Contract v1 is evaluated against Effective Authority Relationship v1.

Each relationship with an attached contract receives one of three outcomes:

- `compliant` — supported static evidence satisfies every applicable contract clause;
- `violation` — supported static evidence contradicts at least one contract clause;
- `unresolved` — no violation is proven, but one or more constrained dimensions lack
  sufficient static evidence.

Violation and unresolved records link back to the stable
`authority_relationship_id` and identify the exact contract clause, expected policy
values and observed evidence. Runtime effectiveness remains `not_verified`.

Examples of high-confidence violations include:

- an observed capability explicitly denied by the contract;
- a resource or destination outside an explicit allowlist;
- an observed IAM role, permission or OAuth scope denied by policy;
- an explicitly disabled approval for a capability that requires approval;
- an MCP server outside the allowed server set;
- an MCP server exposing tools outside an explicit contract allowlist.

An unspecified approval state is not treated as approval. It remains unresolved.
Likewise, missing identity/resource/destination evidence does not become a clean policy
result.

### MCP tool scope

Per-server MCP tool contracts distinguish explicit scope from incomplete evidence.

An explicit server allowlist that exposes tools outside the contract is a violation.
A contract requiring an MCP allowlist is also violated when the relationship is known
to be unrestricted or denylist-only. Dynamic filters remain unresolved unless their
effective tool scope can be reconstructed.

For deny-only MCP clauses, HorusTrace reports unresolved when the server catalogue is
unknown and cannot prove whether the denied tool is reachable.
