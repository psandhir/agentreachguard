# HorusTrace v0.8 deployment-authority natural-cohort baseline

## Execution

The frozen natural cohort from PR #125 was executed for the first time on 2026-09-25.

- Frozen main SHA: `05a40553e9cca3f12ca0cc3131af252aabb75557`
- Execution SHA: `d48b7abe2346aca0e5c9019942ee487920098dcf`
- GitHub Actions run: `36147599276`
- Artifact: `deployment-authority-v08-results` / ID `10870287649`
- Scanner: `horustrace 0.8.0`
- Target applications were fetched at exact SHAs and were not installed, imported or executed.
- Terraform is repository-declared evidence, not verified live cloud state.
- `runtime_effectiveness` remained `not_verified`.

The execution commit differs from the frozen main SHA only by the dedicated one-shot research workflow. No scanner, reconciliation, cohort, deployment-evidence or ground-truth content changed before execution.

## Headline result

The experiment cleanly separates two conclusions.

**Implementation behavior was largely correct:** 9 of 10 adjudicated principals produced exactly the pre-registered v0.8 result. In all nine, HorusTrace resolved the expected deployed identity and reconstructed the expected deployed role set, then conservatively returned `unresolved` because required IAM roles/permissions could not be derived from application-side authority.

**Security classification coverage is the major gap:** the independent ground truth contained 1 aligned, 7 excess-authority, 1 missing-authority and 1 mixed case. Of the nine principals that reached reconciliation, HorusTrace classified all nine as `unresolved`. It therefore produced **0 exact independent security classifications out of 9 evaluable principals**. The tenth case was not classifiable because its intended root workflow agent was not discovered.

This is not evidence that v0.8 makes unsafe positive assertions. It is evidence that the current source-to-IAM bridge is too weak to turn otherwise-successful deployment reconstruction into actionable least-privilege conclusions on these natural repositories.

## Measured layers

| Layer | Natural-cohort result |
| --- | ---: |
| Frozen cases | 10 |
| Expected principal discovered and reconciled | 9 / 10 |
| Expected deployed identity resolved | 9 / 10 |
| Expected deployed role set reconstructed | 9 / 10 |
| Pre-registered v0.8 behavior matched | 9 / 10 |
| Evaluable independent security classifications | 9 |
| Exact independent security classifications | 0 / 9 |
| Observed `unresolved` among evaluable principals | 9 / 9 |
| Required IAM role sets reconstructed as non-empty | 0 / 9 |

## Case results

| Case | Independent truth | HorusTrace | Key role-level adjudication |
| --- | --- | --- | --- |
| natural-001 | excess authority | unresolved | `storage.objectViewer` excess |
| natural-002 | aligned | unresolved | reviewed role set aligned |
| natural-003 | excess authority | unresolved | `discoveryengine.editor`, `storage.admin` excess |
| natural-004 | excess authority | unresolved | `serviceAccountTokenCreator`, `serviceAccountUser` excess |
| natural-005 | mixed | unresolved | `discoveryengine.admin` excess; BigQuery viewer/job roles missing |
| natural-006 | excess authority | expected principal missing | `storage.admin` excess; ADK `Workflow` root not discovered |
| natural-007 | excess authority | unresolved | Datastore, Storage Viewer, Trace and Logging roles adjudicated excess for router |
| natural-008 | missing authority | unresolved | `cloudsql.client` missing |
| natural-009 | excess authority | unresolved | Storage Admin, Secret Manager accessor and Datastore User excess |
| natural-010 | excess authority | unresolved | `storage.admin` excess |

The independent role-level judgments above were frozen before this run. Permission-level role expansion remains unresolved because the study did not pin a Google Cloud role catalogue.

## Finding 1 — deployed-side reconstruction works substantially better than required-side reconstruction

For nine expected principals HorusTrace successfully associated the supplied deployment workload with the intended agent and reconstructed the repository-declared role grants. This is meaningful validation of the v0.8 deployment-evidence path.

The blocker is the opposite side of the comparison. For all nine successfully reconciled principals, the report contained empty `required.roles` and `required.permissions`, with:

- `required_roles`
- `required_permissions`
- and, because role catalogues were intentionally absent, `permissions`

remaining unresolved.

This means v0.8 currently knows **what the workload is granted** much more often than it knows **what the agent needs in IAM terms**.

## Finding 2 — conservative unresolved behavior avoided false least-privilege claims

The nine evaluable cases were all returned as `unresolved`, including the independently aligned case. HorusTrace therefore did not falsely claim that excess or missing authority was proven where its current evidence model could not establish the required IAM side.

That conservative behavior is preferable to inventing an IAM requirement, but it is not yet sufficient for the product goal of identifying real over-privilege and missing-authority conditions from natural source + IaC repositories.

## Finding 3 — ADK 2.0 Workflow is a concrete coverage defect

Natural-006 uses:

`root_agent = Workflow(...)`

from `google.adk.workflow`, with an `LlmAgent` node named `risk_reviewer`.

The current Google ADK adapter's agent types are:

`Agent`, `LlmAgent`, `SequentialAgent`, `ParallelAgent`, `LoopAgent`, and `RemoteA2aAgent`.

It therefore discovers `risk_reviewer` but does not materialize the `Workflow` root as the expected `root_agent`. The deployment evidence was explicitly bound to `root_agent`, so no expected deployed-identity relationship or reconciliation record was produced for that principal.

This should be treated as a scanner coverage issue independent of the IAM-requirement problem.

## Product implications

The v0.8 architecture is not invalidated by this result. The experiment shows that its **deployed-side** model is useful: identity and declared IAM can be reconstructed and kept conservative without executing the target.

The highest-value next improvement is now empirically clear: add a defensible mapping from source-observed managed-service operations/capabilities to required cloud authority. This must remain evidence-backed and should not simply map every generic `data.read` capability to a broad predefined role.

A practical sequence is:

1. fix Google ADK `Workflow` root discovery and rerun natural-006;
2. introduce a versioned GCP required-authority knowledge layer for high-confidence operations such as Cloud SQL connection, BigQuery query/write, Discovery Engine read/search, Vertex model invocation, Secret Manager access and Cloud Tasks enqueue;
3. preserve `unresolved` for ambiguous mappings rather than guessing;
4. expand predefined roles to permissions only from a pinned/explicit role catalogue;
5. rerun this exact frozen cohort and measure movement from `unresolved` to correct aligned/excess/missing/mixed classifications;
6. only after the natural baseline improves, run the six controlled mutations.

## Claims supported by this baseline

A defensible statement after this run is:

> On a frozen 10-case public GCP/Google-ADK natural cohort, HorusTrace v0.8 resolved the intended deployed identity and repository-declared role set for 9 of 10 adjudicated principals, while conservatively leaving all nine least-privilege classifications unresolved because required IAM authority was not derivable from the current application-side model.

It is **not** defensible to claim that v0.8 detected the seven adjudicated natural excess-authority cases. It did not; six reached reconciliation and remained unresolved, while one was blocked by the ADK Workflow discovery gap.
