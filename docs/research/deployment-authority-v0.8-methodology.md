# HorusTrace v0.8 deployment-authority validation study

## Purpose

This study evaluates whether HorusTrace can connect static agent authority to reviewed GCP workload identity and IAM evidence, then correctly classify deployed authority as aligned, excess, missing, mixed, or unresolved.

It is separate from the frozen-90 corpus. Frozen-90 measures scanner robustness and non-regression across public agent repositories; this study measures deployed-authority reasoning against manually adjudicated ground truth.

## Research questions

1. **Identity binding:** can HorusTrace associate an agent with the reviewed GCP workload identity?
2. **Authority reconstruction:** can it reconstruct reviewed roles and permissions, including inheritance and conditional grants represented by Deployment Evidence v1?
3. **Least privilege:** can it distinguish aligned, excess, missing, mixed, and unresolved authority?
4. **Conservative reasoning:** does ambiguous or conditional authority remain unresolved instead of becoming an unsupported claim?
5. **Change detection:** in the mutation cohort, does HorusTrace detect privilege expansion and distinguish it from privilege reduction?
6. **Explainability:** can each adjudicated conclusion be traced to application and infrastructure source evidence?

## Scope

The v0.8 study is intentionally **GCP-only**. Deployment Evidence v1 is provider-neutral, but v0.8 deployed-authority reconstruction is currently mature for GCP. Adding AWS or Azure cases would conflate provider-adapter coverage with reconciliation accuracy.

The target design is:

- 10 natural public application/infrastructure cases;
- 6 controlled security mutations derived from frozen natural cases;
- first-party control fixtures used to validate the harness, excluded from headline empirical counts.

The natural cohort must be frozen before HorusTrace results are used to select or exclude cases.

## Inclusion criteria for natural cases

A candidate qualifies only when all of the following are true:

- the agent framework is supported by the current HorusTrace scanner;
- the repository contains at least one security-relevant agent/tool capability;
- a GCP workload or service-account identity can be adjudicated from source evidence;
- public Terraform/IaC contains IAM bindings relevant to that identity;
- the application and infrastructure revisions can both be pinned to exact 40-character Git commit SHAs;
- sufficient static evidence exists to create reviewed ground truth without executing the target;
- analysis does not require cloud credentials or live cloud API access;
- provenance and licensing permit public research use.

Exclusion reasons must be recorded during candidate screening. Repositories must not be selected because a preliminary HorusTrace run produced an interesting result.

## Evidence model

Each case contains three logically distinct evidence layers:

1. **Application source** — source-observed agent capabilities, identity declarations, tools, resources, destinations, and policy intent.
2. **Terraform authority source** — repository-declared IAM intent. This is not treated as proof of live/effective cloud state.
3. **Deployment Evidence v1** — the normalized deployment/IAM snapshot consumed by `horustrace reconcile`.

All conclusions retain `runtime_effectiveness: not_verified`.

## Ground-truth protocol

Ground truth is written and marked `reviewed: true` before the study runner is allowed to execute a case. Each expected agent records:

- exact agent name;
- expected workload identity;
- expected reconciliation status;
- required roles and permissions;
- deployed unconditional roles and permissions;
- conditional roles and permissions;
- excess roles and permissions;
- missing roles and permissions;
- unresolved dimensions;
- application and infrastructure evidence paths with reviewer rationale.

Ambiguous dynamic expressions, unresolved conditions, unknown custom roles, or insufficient source authority are recorded as unresolved rather than guessed.

## Reproducibility and safety

The harness:

- fetches application and infrastructure repositories only at exact commit SHAs;
- verifies the checked-out revision matches the frozen SHA;
- does not install, import, or execute target applications;
- does not call cloud APIs or test credentials;
- runs the current HorusTrace checkout in a bounded subprocess;
- supplies the checked-out infrastructure tree through `--authority-source`;
- supplies reviewed normalized deployment evidence through `--deployment-evidence`;
- fails closed on invalid study documents, clone errors, SHA mismatches, timeouts, or malformed JSON output.

## Primary measurements

The final report records:

- case pass/fail against reviewed ground truth;
- agent identity match/mismatch evidence;
- expected versus observed required/deployed/excess/missing role and permission sets;
- conditional and unresolved authority agreement;
- reconciliation classification confusion matrix across `aligned`, `excess_authority`, `missing_authority`, `mixed`, and `unresolved`;
- mutation detection results;
- unresolved-evidence categories and product limitations discovered during adjudication.

Headline results must keep execution failures separate from semantic mismatches.

## Mutation cohort

The first mutation set should cover one security property at a time:

1. add a broad role;
2. introduce inherited privilege;
3. add a sensitive conditional grant;
4. remove a required permission;
5. substitute the workload identity;
6. remove previously excessive authority and verify that it is classified as an improvement rather than a regression.

Mutation cases must retain provenance to their frozen natural base case and state the intended security delta before execution.

## Study phases

1. Land this methodology and harness with an empty cohort.
2. Discover a broader candidate pool and document inclusion/exclusion decisions.
3. Freeze ten natural app/IaC pairs at exact SHAs.
4. Complete manual ground-truth adjudication before executing HorusTrace against the cohort.
5. Add six controlled mutation cases.
6. Execute the study, separate product defects from evidence gaps, fix defects, and rerun the same frozen cohort.
7. Preserve the final JSON and Markdown results as the v0.8 deployment-authority baseline.

## Running the harness

Validate the study contract without network access:

```bash
python scripts/deployment_authority_study.py --validate-only
```

Execute the frozen cohort and retain machine-readable and reviewable output:

```bash
python scripts/deployment_authority_study.py \
  --output-json deployment-authority-v08.json \
  --output-markdown deployment-authority-v08.md
```

The initial cohort is intentionally empty. A zero-case validation confirms only that the study contract is structurally valid; it is not an empirical result.
