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
