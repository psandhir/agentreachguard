# Deployment evidence

HorusTrace v0.8 consumes an explicit, local deployment evidence snapshot so deployed
authority can be reconciled without executing an agent or contacting a production cloud
API.

## Contract

The version 1 document is JSON or YAML:

```yaml
schema_version: 1
provider: gcp
source: cloud-asset-export

workloads:
  - workload_id: projects/prod/locations/europe-west1/services/support-agent
    kind: cloud_run
    name: support-agent
    identity: support-agent@prod.iam.gserviceaccount.com
    agent: support
    project: prod
    region: europe-west1

iam_bindings:
  - principal: serviceAccount:support-agent@prod.iam.gserviceaccount.com
    role: roles/secretmanager.secretAccessor
    scope:
      kind: project
      name: prod
    inherited_from:
      kind: folder
      name: "12345"

role_permissions:
  roles/secretmanager.secretAccessor:
    - secretmanager.versions.access
    - secretmanager.versions.get
```

`agent` is an explicit application-to-workload binding. HorusTrace does not use fuzzy
name matching to invent a deployment relationship.

Conditional IAM bindings are retained as evidence. A later authority resolver must keep
their runtime applicability unresolved unless the condition is independently evaluated.

The loader rejects unknown schema fields, oversized files, unsupported formats and
invalid field types. This is an evidence input, not a declaration that observed
production authority is safe.
