# HorusTrace v0.8 natural deployment-authority cohort

## Freeze status

The natural cohort was frozen on 2026-09-25 after PRs #122-#124 established the study contract, candidate-screening record, and independent security-ground-truth layer.

**No HorusTrace scan or reconciliation output was used to select, replace, or label these cases.**

The frozen cohort contains 10 natural cases across 9 public repositories. Application and infrastructure revisions are pinned to exact 40-character Git SHAs. The study runner will fetch those exact revisions and will not install, import, or execute target applications.

## Evidence semantics

The normalized Deployment Evidence v1 files are manually projected from repository-declared Terraform at the frozen revision.

Where a Terraform project ID or account expression is parameterized, the normalized evidence preserves that parameter symbolically (for example, `${var.project_id}`). This is intentional. The evidence represents **repository-declared deployment/IAM intent**, not a claim about a live Google Cloud project.

No live cloud API was queried. No credentials were tested. `runtime_effectiveness` remains `not_verified`.

The natural study is adjudicated at **IAM role granularity**. Permission-level role expansion is left unresolved because the cohort does not include a frozen Google Cloud IAM role catalogue. The study therefore must not claim permission-level least-privilege precision from these natural cases.

## Frozen cases

| Case | Repository | Principal agent | Human classification | Key adjudication |
| --- | --- | --- | --- | --- |
| natural-001 | Metafiziks/gcp-search-agent | `search_agent` | excess authority | Runtime identity receives `storage.objectViewer` although reviewed agent source uses Discovery Engine/Vertex/BigQuery rather than direct GCS reads. |
| natural-002 | dhanyashree9513-byte/adk-multiagent-production-template | `root_agent` source alias | aligned | Managed Agent Engine roles match reviewed Firestore, Vertex AI and staged-artifact needs at role granularity. |
| natural-003 | arjunprabhulal/adk-advanced | `root_agent` | excess authority | Local weather/time tools plus model invocation are deployed with Discovery Engine Editor and Storage Admin. |
| natural-004 | Prostecki/med-voice | `med_voice_root` | excess authority | Runtime backend receives service-account token creation and act-as roles without reviewed agent-runtime evidence requiring impersonation. |
| natural-005 | KristionB/sql-adk-agent | `db_ds_multiagent` | mixed | BigQuery-backed analysis lacks repository-declared BigQuery viewer/job roles while the runtime identity receives Discovery Engine Admin. |
| natural-006 | esoltys/ambient-expense-agent | `root_agent` | excess authority | Expense workflow receives project-level Storage Admin without reviewed runtime storage-administration need. |
| natural-007 | mahieddine-ichir/hello-google-agents | `adhesion_router` | excess authority | Router delegates to Reasoning Engines but receives Datastore, GCS viewer, Trace and Log Writer roles beyond the reviewed router need. |
| natural-008 | young-monk/shopright-ecommerce | `shopright_assistant` | missing authority | Chatbot mounts/connects to Cloud SQL but its dedicated service account lacks repository-declared `roles/cloudsql.client`. |
| natural-009 | LaurentVeyssier/Ask-your-data-genie | `root_agent` | excess authority | Local code-execution/data-analysis agent receives Storage Admin, Secret Accessor and Datastore User beyond reviewed runtime need. |
| natural-010 | kuldeepjain1920/expense-agent | `review_agent` | excess authority | Literal expense-review agent receives project-level Storage Admin despite no reviewed runtime storage-administration operation. |

### Pre-run class distribution

- aligned: **1**
- excess authority: **7**
- missing authority: **1**
- mixed: **1**
- unresolved: **0** at the human role-level classification

This distribution is a consequence of manual source adjudication, not HorusTrace output. It should not be interpreted as prevalence in the broader ecosystem because this is a purposive evidence-rich validation cohort, not a random sample.

## Expected v0.8 behavior before execution

The independent human classification above is intentionally different from the expected v0.8 implementation behavior.

For every frozen natural case, the current v0.8 evidence model is expected to leave required IAM roles/permissions unresolved because application-side effective-authority relationships generally do not contain the deployed service-account role set, and `--authority-source` only enriches an exact service-account identity already discovered in the application graph.

Accordingly, the pre-registered `expected_horustrace` state for each principal is:

- deployed identity: explicitly bound by Deployment Evidence v1;
- deployed roles: reconstructed from normalized repository-declared IAM evidence;
- deployed permission expansion: unresolved;
- required roles: unresolved;
- required permissions: unresolved;
- reconciliation status: `unresolved`.

This is **not** the security ground truth. It is the implementation oracle used to distinguish “the product behaved according to v0.8 semantics” from “the product correctly identified the independently adjudicated security condition.”

## Correlated deployment family

Three cases use closely related Google Agent Starter Pack-style deployment scaffolding:

- natural-006 — ambient expense agent;
- natural-009 — Ask Your Data;
- natural-010 — expense agent.

They are retained because their application-side authority differs materially, but they are not statistically independent infrastructure observations. Final conclusions must state this explicitly and should not turn the 7/10 excess-authority count into an ecosystem prevalence estimate.

## Replacement made before execution

The initially shortlisted `lastingyeh/adk-insurance-recommendation-agent` was replaced before cohort execution.

Its agent is created through a factory and then assigned using `root_agent = create_agent(...)`. The current static Google ADK adapter materializes direct `Agent(...)` / workflow constructor assignments and may not materialize that factory-created agent. Keeping the case would mix agent-discovery coverage with deployed-authority evaluation.

The reserve `kuldeepjain1920/expense-agent` was promoted instead because it contains a literal ADK `Agent` declaration and explicit application-service-account IAM evidence.

## What happens next

After this freeze PR lands, the next phase is the first empirical execution:

```bash
python scripts/deployment_authority_study.py \
  --output-json deployment-authority-v08-natural.json \
  --output-markdown deployment-authority-v08-natural.md
```

The first run must be preserved unchanged. Any mismatch must then be classified as one of:

1. expected implementation behavior;
2. HorusTrace product defect;
3. scanner/framework coverage gap;
4. evidence-normalization error;
5. human adjudication error;
6. legitimate unresolved ambiguity.

Product fixes, if any, happen only after that first frozen result is recorded.
