# Deployment Authority Study — post-PR #128 baseline

## Execution

PR #128 was merged to main at commit `85da4262f60fc7c6e8085076f3acaa8e3b8fec7b`.

The frozen 10-case natural cohort was rerun from that exact main code on 2026-09-25:

- validation run: `36153783553`
- artifact: `10873300171`
- validation branch SHA: `feb278186bc3c17167b6166b2596e2edb1bb2b3d`
- scanner version: `0.8.0`
- target repos remained exact-SHA, static-only inputs
- no target install/import/execution
- no live cloud API calls
- `runtime_effectiveness` remained `not_verified`

The validation branch differs from merged main only by the one-shot workflow used to run the study.

## What changed from the pre-fix baseline

Before the required-authority work, the natural cohort collapsed to `unresolved`: after the ADK Workflow fix all 10 expected principals were discovered and reconciled, but no natural case had a source-derived IAM requirement strong enough to change its security status.

After #128:

| Metric | Post-#128 |
| --- | ---: |
| Frozen natural cases | 10 |
| Observed `missing_authority` | 2 |
| Observed `unresolved` | 8 |
| Cases with positive required-role evidence | 4 |
| Positive required roles inferred | 5 |
| Positive roles matching frozen required-role sets | 4 |
| Frozen missing roles detected exactly | 2 / 3 |
| Frozen excess roles detected | 0 / 15 |
| Exact frozen security classifications | 1 / 10 |

The old v0.8 implementation oracle now passes only 6/10 cases. That is expected and desirable: #128 intentionally changes the implementation contract. The four changed cases are natural-001, natural-004, natural-005 and natural-008.

## Case-level movement

| Case | Frozen security truth | Post-#128 status | New source-backed required authority |
| --- | --- | --- | --- |
| natural-001 | excess authority | unresolved | `roles/discoveryengine.viewer` |
| natural-002 | aligned | unresolved | none |
| natural-003 | excess authority | unresolved | none |
| natural-004 | excess authority | unresolved | `roles/cloudtasks.enqueuer` |
| natural-005 | mixed | **missing authority** | `roles/bigquery.dataViewer`, `roles/bigquery.jobUser` |
| natural-006 | excess authority | unresolved | none |
| natural-007 | excess authority | unresolved | none |
| natural-008 | missing authority | **missing authority** | `roles/discoveryengine.viewer` |
| natural-009 | excess authority | unresolved | none |
| natural-010 | excess authority | unresolved | none |

## Finding 1 — natural-005 is the first clean natural missing-IAM detection

The frozen human adjudication for `natural-005` classified the case as mixed:

- required: `roles/aiplatform.user`, `roles/bigquery.dataViewer`, `roles/bigquery.jobUser`
- deployed: `roles/aiplatform.user`, `roles/discoveryengine.admin`
- missing: BigQuery Data Viewer + Job User
- excess: Discovery Engine Admin

Post-#128 HorusTrace derives both BigQuery roles from the reachable agent path and proves that both are absent from the repository-declared runtime identity.

That means the missing-authority half of the independent adjudication is now detected exactly.

The overall observed status is still `missing_authority`, not `mixed`, because HorusTrace deliberately refuses to label `roles/discoveryengine.admin` excess while the required-role baseline is incomplete. This is the intended conservative asymmetry introduced in #128.

## Finding 2 — natural-008 exposed an adjudication omission

The frozen manual review for `natural-008` identified `roles/cloudsql.client` as missing. Post-#128 HorusTrace still does not infer that requirement.

However, HorusTrace now proves another missing role: `roles/discoveryengine.viewer`.

Post-hoc inspection of the already-pinned source confirms:

1. `ai/chatbot/main.py` imports and exposes `rag.search_products` as the chatbot tool path.
2. `ai/chatbot/rag.py` lazily creates `google.cloud.discoveryengine_v1.RankServiceClient`.
3. That path invokes `rank(...)`.
4. The frozen deployment evidence gives the chatbot identity `roles/aiplatform.user`, `roles/bigquery.dataEditor` and `roles/cloudtrace.agent`, but no Discovery Engine role.

Therefore the new HorusTrace finding is source-backed and deployment-backed. The original frozen ground-truth file is intentionally **not edited**. Instead, this repository records a post-hoc adjudication note stating that the manual review omitted an additional missing Discovery Engine requirement.

This is useful evidence that the study can challenge the reviewer, not merely grade the product.

## Finding 3 — positive authority evidence is improving faster than complete authority reconstruction

`natural-001` and `natural-004` now contain correct positive requirements:

- Discovery Engine Viewer for the search agent;
- Cloud Tasks Enqueuer for the Med Voice agent.

Those requirements are already present in the deployed role sets, so no missing-authority finding is produced.

Both cases remain `unresolved` because the inferred role sets are explicitly incomplete. That prevents HorusTrace from treating every other deployed role as excess merely because it has not yet found corresponding source evidence.

Across the frozen manual role sets, #128 recovers 4 of 37 pre-adjudicated required roles. That is still low coverage, but it is qualitatively different from the pre-fix baseline of zero source-derived IAM requirements.

## Finding 4 — excess-authority detection remains the main unresolved product gap

The frozen human review contains 15 role-level excess grants across the ten natural cases.

Post-#128 HorusTrace proves **0/15** of those roles as excess.

This is expected under the current safety model: positive source evidence is enough to prove that a missing role is required, but absence of source evidence is not enough to prove that a deployed role is unnecessary. Excess detection requires a complete-enough required-authority baseline.

This is now the dominant gap in the deployment-authority product direction.

## Quantitative interpretation

Against the frozen pre-run role lists:

- required-role recovery: **4 / 37**;
- exact frozen missing-role recovery: **2 / 3**;
- frozen excess-role recovery: **0 / 15**.

The natural-008 Discovery Engine finding is excluded from those frozen-truth numerators because it was not in the pre-run manual truth. If the post-hoc adjudication note is considered, HorusTrace has surfaced a third valid missing role, while `roles/cloudsql.client` remains undetected.

## Next engineering target

The next highest-value improvement is **cross-layer required-authority evidence**, beginning with Cloud Run + Cloud SQL:

- application source uses a Cloud SQL Unix-socket/database path;
- Terraform binds a Cloud SQL instance volume/socket into the agent workload;
- the workload identity is known from Deployment Evidence;
- therefore `roles/cloudsql.client` is a defensible positive minimum requirement.

This is stronger than a generic heuristic because it joins application behavior, deployment wiring and workload identity.

After that, the product still needs a principled way to decide when the required-authority baseline is complete enough to support excess-authority conclusions. Until completeness is established, excess should continue to fail closed.

## Supported claim after #128

> On the frozen 10-case public GCP natural cohort, HorusTrace now derives source-backed GCP IAM requirements in four cases and proves missing deployed authority in two. In one mixed case it exactly identifies both independently adjudicated missing BigQuery roles; in another case it surfaced an additional source-backed missing Discovery Engine role that the pre-run manual review had omitted. Excess-authority classification remains unresolved because required-role baselines are intentionally incomplete.

Do not describe these as verified live-cloud findings. They are findings against repository-declared deployment/IAM evidence at pinned commits.
