# GCP IAM authority enrichment

HorusTrace can enrich statically discovered GCP service-account identities with direct
IAM bindings exported from Google Cloud Asset Inventory (CAI).

This is an **optional offline evidence input**. HorusTrace does not authenticate to
Google Cloud, call a cloud API, or execute the target repository when this feature is
used.

## Export IAM policy evidence

Cloud Asset Inventory can export `IAM_POLICY` content to Cloud Storage as
newline-delimited JSON. Each line is an Asset record containing the resource name,
asset type, optional ancestry and the IAM policy set on that asset.

For example:

```bash
gcloud asset export \
  --project=PROJECT_ID \
  --content-type=iam-policy \
  --output-path=gs://BUCKET/horustrace-iam.ndjson
```

Download the resulting object into the trusted CI or analysis workspace before
running HorusTrace.

The IAM export is cloud authorization evidence and can contain resource names,
principals, role assignments, ancestry and IAM Conditions. Treat it as sensitive
security metadata even though it should not contain service-account private keys.

## Enrich a scan

```bash
horustrace scan . \
  --gcp-iam-export horustrace-iam.ndjson \
  --format json \
  --fail-on none \
  --output report.json
```

The same evidence can enrich the Agent Dependency Graph or AIBOM:

```bash
horustrace graph . \
  --gcp-iam-export horustrace-iam.ndjson \
  --output adg.json

horustrace aibom . \
  --gcp-iam-export horustrace-iam.ndjson \
  --output aibom.json
```

## Matching semantics

HorusTrace deliberately requires strong static identity evidence before applying
cloud authority:

- only identities already normalized as `provider: gcp` are eligible;
- only exact Google service-account principals are matched;
- both `serviceAccount:name@project.iam.gserviceaccount.com` and the equivalent
  bare service-account email are canonicalized to the same principal;
- user, group, domain and fuzzy/name-only matches are ignored;
- duplicate semantic IAM bindings are de-duplicated.

An imported role is therefore attached only when the agent graph and the cloud export
identify the same service-account principal.

## Direct and conditional bindings

An unconditional exact binding is added to the identity's observed `roles` and can
participate in normal Layer-3 identity rules.

For example, if an agent declares:

```yaml
identities:
  - name: invoice-agent@acme-prod.iam.gserviceaccount.com
    provider: gcp
```

and the export contains an unconditional `roles/owner` binding for that exact
principal, HorusTrace can report `IDN001` because the cloud evidence establishes a
broad administrative role.

IAM Conditions are handled more conservatively. A conditional binding is retained in
the identity's `gcp_iam_bindings` evidence and provenance, but its role is **not**
promoted to an unconditional `Identity.roles` value. This prevents a time-, resource-
or request-constrained role from being reported as if it always applied.

## Reported evidence

When an export is supplied, JSON output includes an `enrichment.gcp_iam_export`
audit object with:

- export path;
- Asset records processed;
- service-account binding observations;
- matched logical identities;
- unique matched bindings;
- unique matched conditional bindings.

Enriched ADG identity nodes retain direct binding evidence, including:

- principal;
- role;
- resource name;
- asset type;
- resource ancestors from the export;
- IAM Condition fields when present;
- source line in the local NDJSON export.

Console output includes the same aggregate enrichment counts.

## Scope boundary

This first GCP authority-enrichment slice models **direct IAM policy evidence from the
provided export**. It intentionally does not yet claim complete effective cloud
authorization.

In particular, it does not currently:

- calculate IAM inheritance across organization, folder and project ancestors;
- expand Google groups into their members;
- expand predefined or custom roles into individual permissions;
- evaluate whether an IAM Condition is true for a particular request;
- resolve principal access boundary or deny policy effects;
- discover the deployed runtime service account if it was not already normalized by
  static analysis;
- query Cloud Asset Inventory, IAM Policy Analyzer, or any other live Google API.

The export's `ancestors` values and IAM Conditions are retained as evidence so later
effective-authority analysis can reason over them without discarding source context.

A role observed in an export is evidence of cloud configuration, not proof that an
agent has successfully exercised the permission at runtime.
