# Offline GCP IAM authority enrichment

HorusTrace can enrich already-discovered Google Cloud service-account identities with
offline Cloud Asset Inventory IAM policy evidence. It accepts either IAM policy search
results or an `exportAssets` IAM-policy snapshot.

This is an optional control-plane evidence source. HorusTrace does not authenticate to
Google Cloud during a normal scan and does not execute target code.

## Export IAM policy search results

Use Cloud Asset Inventory to export the IAM policies visible to the caller and scope:

```bash
gcloud asset search-all-iam-policies \
  --scope=projects/PROJECT_ID \
  --format=json > /secure/path/gcp-iam.json
```

Organization or folder scopes can also be exported when the caller has the required
Cloud Asset Inventory permissions.

The supported input is the native JSON shape returned by
`search-all-iam-policies`: each result contains a resource and a nested
`policy.bindings[]` list with roles and members. HorusTrace accepts either:

- the JSON list emitted by `gcloud ... --format=json`;
- a REST response object with a top-level `results` list;
- one individual IAM search result object.

See the Google Cloud documentation:
<https://docs.cloud.google.com/asset-inventory/docs/search-allow-policies>

### Alternative: export an IAM-policy asset snapshot

For larger or repeatable snapshots, Cloud Asset Inventory can export IAM-policy Asset
records to Cloud Storage:

```bash
gcloud asset export \
  --project=PROJECT_ID \
  --content-type=iam-policy \
  --output-path=gs://BUCKET/horustrace-iam.ndjson
```

Download the resulting object to the trusted analysis workspace before invoking
HorusTrace. Cloud Storage exports are newline-delimited Asset JSON records. HorusTrace
normalizes each Asset's `name`, `assetType`, `iamPolicy.bindings[]` and
`ancestors` into the same internal grant model used for IAM policy search results.

See:
<https://docs.cloud.google.com/asset-inventory/docs/export-cloud-storage>

## Enrich a scan

```bash
horustrace scan . \
  --gcp-iam-snapshot /secure/path/gcp-iam.json \
  --format json \
  --fail-on high
```

The same snapshot can be supplied to graph and AIBOM output:

```bash
horustrace graph . \
  --gcp-iam-snapshot /secure/path/gcp-iam.json \
  --output adg.json

horustrace aibom . \
  --gcp-iam-snapshot /secure/path/gcp-iam.json \
  --output aibom.json
```

The snapshot does not need to live inside the repository.

## Correlation model

The first implementation intentionally correlates only Google Cloud service accounts
that HorusTrace has already discovered in the application or infrastructure model.

For example, if a manifest or supported source construct identifies:

```text
agent-sa@my-project.iam.gserviceaccount.com
```

HorusTrace can match Cloud Asset IAM members expressed as:

```text
serviceAccount:agent-sa@my-project.iam.gserviceaccount.com
```

or service-account resource names ending in that email.

Unrelated service accounts, users, groups, domains and public principals in the
snapshot are not added to the Agent Dependency Graph.

## Enriched evidence

For a matched identity HorusTrace adds:

- observed IAM roles;
- observed IAM resources;
- asset type for each grant when present;
- whether each binding is conditional;
- `observed` provenance pointing to the supplied snapshot.

Layer-3 identity rules then run over the enriched identity. For example, an observed
`roles/owner` grant can trigger `IDN001` for the agent that uses the matched
service account.

The ADG identity node records the observed resource scopes, normalized IAM grants and
marks the authority source as `gcp_iam_snapshot`. For `exportAssets` input, grant
records also retain the exported resource ancestry.

Coverage resolution includes summary counts for:

- IAM search results;
- service-account principals;
- grants;
- matched identities and grants;
- unmatched service-account principals;
- conditional grants.

## IAM conditions

Conditional bindings are preserved as conditional observations. HorusTrace does not
evaluate Common Expression Language (CEL) IAM condition expressions in this
milestone.

When a broad administrative role is observed **only** through conditional bindings,
the identity finding retains the finding but includes an explicit limitation that the
condition was not evaluated.

An unconditional administrative grant remains unconditional even if the same identity
has other conditional grants.

## Security and privacy properties

The snapshot parser:

- is offline and does not call Google Cloud;
- caps snapshot size at 32 MiB;
- caps IAM search results and normalized grants;
- fails closed when an explicitly supplied snapshot is malformed;
- does not execute or import target repository code;
- does not print credential material;
- does not retain IAM CEL condition expressions in normalized graph evidence;
- records only the snapshot filename in finding provenance rather than an absolute
  workstation or runner path.

IAM policy exports can contain sensitive organization and principal information. Keep
the export in an appropriately protected location; committing it to the scanned
repository is not required.

## Current limitations

This first enrichment milestone does **not** yet:

- expand predefined or custom IAM roles into full permission sets;
- evaluate IAM condition expressions;
- compute effective inheritance across organization, folder and project hierarchy;
- resolve group membership;
- model deny policies or principal access boundary policies;
- query Cloud Asset Inventory or IAM Policy Analyzer directly;
- prove that the supplied snapshot is complete or current;
- apply one external cloud snapshot to `horustrace diff`.

The last limitation is intentional. Code revisions and a point-in-time cloud snapshot
have different time semantics. Change-aware cloud authority analysis should compare
versioned/timestamped authority evidence rather than silently applying one current
snapshot to both Git revisions.
