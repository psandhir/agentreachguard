# HorusTrace v0.8 deployment-authority candidate screening

## Status

This document records Phase 2 candidate discovery for the deployment-authority validation study.

The methodology was merged in PR #122 before this screening began. **No HorusTrace scan, reconciliation result, finding count, or policy outcome was used to select candidates.** Selection is based only on repository structure, framework support, public application evidence, public GCP Terraform/IAM evidence, and the ability to adjudicate a workload identity from source.

The shortlist below is **not yet the frozen cohort**. The recorded SHAs are the revisions observed during screening. The next phase will manually adjudicate ground truth and then freeze exactly ten natural cases at exact SHAs.

## Discovery approach

The search intentionally started broader than the target cohort. Candidate discovery covered Google ADK, Vertex AI Agent Engine/Reasoning Engine, Cloud Run agent deployments, LangGraph/GCP combinations, CrewAI/GCP combinations, Pydantic AI/GCP combinations, and generic agentic GCP/Terraform repositories.

A positive screen required all of the following to be established from public source at an observed revision:

| Requirement | Screening interpretation |
| --- | --- |
| Supported application | A concrete agent definition using a framework HorusTrace currently recognizes |
| Security-relevant behavior | Tools, data access, delegated agents, external services, or other authority-relevant behavior |
| GCP IaC | Terraform or equivalent repository-declared deployment evidence |
| Runtime identity | An explicit or adjudicable workload/service identity |
| IAM authority | Roles/permissions bound to that runtime or managed service identity |
| Reproducibility | Public repository and exact revision available for later freezing |
| Static-only safety | No need to install, import, execute the target, or contact live cloud APIs |

A negative search result is not treated as proof that evidence does not exist. “Not shortlisted” means the bounded screening pass did not establish enough evidence to satisfy the study contract reproducibly.

## Provisional adjudication shortlist

| Candidate | Observed SHA | Application evidence | Terraform/IAM evidence | Identity basis | Deployment shape |
| --- | --- | --- | --- | --- | --- |
| `lastingyeh/adk-insurance-recommendation-agent` | `90e9b624759248b168a0df93f5ddca35966d1027` | `app/agent.py` | `deployment/terraform/modules/agent_infrastructure/iam.tf` | `google_service_account.app_sa` | Cloud Run |
| `Metafiziks/gcp-search-agent` | `01f1ca76eceae91bafd553c96ba483c250cc4d70` | `src/agent/agent.py` | `terraform/iam.tf` | `google_service_account.agent` | Cloud Run |
| `dhanyashree9513-byte/adk-multiagent-production-template` | `aaddf141aa6f93555fce81cf606667747efe0140` | `customer_support_mas/agents/root/agent.py` | `terraform/modules/core/iam.tf` | app/managed Vertex identities | Agent Engine + Cloud Run |
| `arjunprabhulal/adk-advanced` | `893da057599708b77f1d95d1dd73d9b45e2ddfbd` | `4_adk_deploy_cloudrun/adk_agent_cloudrun_demo/app/agent.py` | matching `deployment/terraform/iam.tf` | deployment app SA | Cloud Run |
| `Prostecki/med-voice` | `c2b73cf886f91b49fbd348e1bc9f29d3b0cb479d` | `backend/app/agents/med_voice_agent/agent.py` | `infra/terraform/iam.tf` | `google_service_account.backend_sa` | Cloud Run |
| `KristionB/sql-adk-agent` | `bf8c3c702a6906cc4735b4ab3ae94548c9e0f574` | `sql_agent/agent.py` | `terraform/main.tf` | Reasoning Engine managed SA + compute identity | Vertex AI Reasoning Engine |
| `esoltys/ambient-expense-agent` | `9d22d27f6650967a14d4c2e2ce85fd6591ebb297` | `expense_agent/agent.py` | `deployment/terraform/single-project/iam.tf` | `google_service_account.app_sa` + Vertex service identity | Agent Starter Pack |
| `mahieddine-ichir/hello-google-agents` | `66c811e7a682a9d4c1896f9e125c6666b93e806c` | `router-agent/agent.py` | `terraform/iam.tf` | `google_service_account.agent_sa` | Cloud Run + Reasoning Engines |
| `young-monk/shopright-ecommerce` | `8ac94f1324d8363abd3b4cd663b46c8ab7e80296` | `ai/chatbot/main.py` | `infra/terraform/main.tf` | `google_service_account.chatbot_sa` | Multi-service Cloud Run |
| `LaurentVeyssier/Ask-your-data-genie` | `5323dd78abf04b137d093d0bfce70cdab586982b` | `app/agent.py` | `deployment/terraform/single-project/iam.tf` | `google_service_account.app_sa` | Agent Starter Pack |

These ten are eligible for **manual adjudication**, not automatically accepted into the final cohort. In particular, the two Agent Starter Pack-style deployments are correlated at the infrastructure level. During ground-truth review we should keep both only if their application-side authority creates materially different cases; otherwise one should be replaced by a reserve.

## Important exclusions and near misses

Several repositories looked strong from names or descriptions but failed a contract requirement when source evidence was inspected:

| Repository | Disposition | Reason |
| --- | --- | --- |
| `Sanjay-AI-ML/customer-ai-agent` | exclude | Strong Cloud Run IAM, but application uses a custom `GeminiAgent` wrapper rather than a currently supported framework. |
| `Nazareno95/terraform-gcp-event-driven-adk-agent` | exclude | Strong Terraform IAM, but observed `agent/app.py` is a Flask event processor with deterministic decision logic, not a supported ADK agent definition. |
| `dantesstacksblog/gcp-ai-support-agent` | exclude | Excellent runtime service-account IAM, but application is a custom `SupportAgent`. |
| `JohnSite07/G_ADK_Project_1` | defer | ADK application and Cloud Run Terraform are present, but the service does not declare an explicit runtime service account/IAM baseline sufficient for this study. |
| `timini/adk-minimal-deployment` | defer | Genuine ADK application and Terraform, but observed Terraform only establishes APIs/staging storage and does not provide enough runtime IAM evidence. |
| `bhardwaju/terraform-google-multi-tenant-agentic-ai` | exclude | Infrastructure-focused Terraform; paired supported application was not established. |
| `kuldeepjain1920/expense-agent` | reserve | App + Terraform structure is promising, but deployment scaffold is highly correlated with selected Agent Starter Pack cases. |
| `geetika-geet/ambient-expense-agent` | reserve | Same correlation concern as above. |
| `NerdForData/Smart-Shop-AI` | defer | Agent and Terraform structure found, but supported-framework + runtime-IAM pairing was not established. |
| `GreetEat/greeteat-paperclip` | exclude | Rich workload IAM, including runtime service-account roles, but no supported agent-framework definition was established. |
| `okahu-demos/adk-travel-agent` | defer | ADK application established; paired Terraform runtime IAM was not established. |
| `axmostech/devfest-2025-adk-secure-deploy` | defer | ADK application established; paired Terraform runtime IAM was not established. |
| `cwest/adk-mcp-polyglot-tools` | defer | ADK/MCP application established; paired Terraform runtime IAM was not established. |

The candidate registry under `research/deployment-authority-v08/candidates.yaml` records additional discovery-only repositories. Those entries are retained so later work does not silently cherry-pick or forget candidates that were considered.

## Cohort characteristics

The provisional shortlist deliberately contains more than trivial “hello agent” cases. It includes multi-agent delegation, MCP/tool use, data/BigQuery access, Vertex AI Search, Cloud Run runtime identities, managed Reasoning Engine identities, and mixed application/managed-service IAM.

There is still a concentration in Google ADK. For v0.8 this is acceptable because the deployed-authority layer being tested is GCP-specific and ADK currently provides the strongest public pairing of analyzable agent source with Terraform IAM. The final report must describe this population honestly rather than generalizing the results to all agent frameworks or all cloud providers.

## Next phase

Phase 3 is manual ground-truth adjudication and cohort freezing. For each shortlisted case we will:

1. verify the observed commit is still fetchable and freeze the exact SHA;
2. identify the exact normalized HorusTrace agent name(s);
3. map application workload/deployment hints to the runtime identity;
4. enumerate required authority from application source;
5. enumerate repository-declared IAM from Terraform, including conditional or managed-service authority;
6. author normalized Deployment Evidence v1;
7. author reviewed ground truth with file-path provenance;
8. only after all ten cases are reviewed, populate `cohort.yaml` and run HorusTrace.

If any shortlisted case cannot support defensible ground truth, it is replaced based on the recorded screening evidence—not based on HorusTrace output.
