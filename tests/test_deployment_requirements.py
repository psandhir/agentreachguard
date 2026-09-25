from pathlib import Path

from horustrace.authority_reconciliation import authority_reconciliation_report
from horustrace.deployment_evidence import (
    DeploymentEvidenceBundle,
    DeploymentWorkloadEvidence,
)
from horustrace.deployment_requirements import (
    enrich_cross_layer_required_authority,
)
from horustrace.models import Agent, Graph


IDENTITY = "shopright-chatbot@prod-project.iam.gserviceaccount.com"


def _write_app(root: Path, *, database: bool = True) -> None:
    root.mkdir()
    body = """
from google.adk.agents import LlmAgent
"""
    if database:
        body += """
import asyncpg
from config import DATABASE_URL


async def startup():
    return await asyncpg.create_pool(DATABASE_URL)
"""
    body += """
root_agent = LlmAgent(
    name="shopright_assistant",
    model="gemini-flash-latest",
)
"""
    (root / "agent.py").write_text(body, encoding="utf-8")


def _write_infra(
    root: Path,
    *,
    account_id: str = "shopright-chatbot",
    cloud_sql: bool = True,
) -> None:
    root.mkdir()
    cloud_sql_block = """
    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.postgres.connection_name]
      }
    }
    containers {
      env {
        name  = "DATABASE_URL"
        value = "postgresql://user:pass@/db?host=/cloudsql/project:region:db"
      }
      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }
    }
""" if cloud_sql else """
    containers {
      env {
        name  = "DATABASE_URL"
        value = "postgresql://db.internal/app"
      }
    }
"""
    (root / "main.tf").write_text(
        f"""
resource "google_service_account" "chatbot_sa" {{
  account_id = "{account_id}"
}}

resource "google_cloud_run_v2_service" "chatbot" {{
  name = "chatbot-service"

  template {{
    service_account = google_service_account.chatbot_sa.email
{cloud_sql_block}
  }}
}}
""",
        encoding="utf-8",
    )


def _bundle(identity: str = IDENTITY) -> DeploymentEvidenceBundle:
    return DeploymentEvidenceBundle(
        provider="gcp",
        source="test",
        workloads=(
            DeploymentWorkloadEvidence(
                workload_id="cloud-run://chatbot",
                kind="cloud_run",
                name="chatbot-service",
                identity=identity,
                agent="shopright_assistant",
                project="prod-project",
            ),
        ),
    )


def test_cloud_sql_role_requires_application_and_workload_wiring(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    infra = tmp_path / "infra"
    _write_app(app)
    _write_infra(infra)
    graph = Graph(agents=[Agent(name="shopright_assistant")])

    result = enrich_cross_layer_required_authority(
        graph,
        app,
        infra,
        _bundle(),
    )

    required = graph.agents[0].metadata["deployment_required_authority"]
    assert required["roles"] == ["roles/cloudsql.client"]
    assert required["roles_complete"] is False
    assert required["evidence"][0]["rule"] == "gcp.cloud_run.cloud_sql_socket"
    assert result.application_database_evidence == 1
    assert result.cloud_sql_workloads == 1
    assert result.matched_agents == 1
    assert result.required_roles_added == 1


def test_cloud_sql_role_is_not_inferred_for_identity_mismatch(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    infra = tmp_path / "infra"
    _write_app(app)
    _write_infra(infra, account_id="different-workload")
    graph = Graph(agents=[Agent(name="shopright_assistant")])

    result = enrich_cross_layer_required_authority(
        graph,
        app,
        infra,
        _bundle(),
    )

    assert "deployment_required_authority" not in graph.agents[0].metadata
    assert result.cloud_sql_workloads == 1
    assert result.matched_agents == 0


def test_cloud_sql_role_is_not_inferred_without_cloud_sql_mount(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    infra = tmp_path / "infra"
    _write_app(app)
    _write_infra(infra, cloud_sql=False)
    graph = Graph(agents=[Agent(name="shopright_assistant")])

    result = enrich_cross_layer_required_authority(
        graph,
        app,
        infra,
        _bundle(),
    )

    assert "deployment_required_authority" not in graph.agents[0].metadata
    assert result.cloud_sql_workloads == 0
    assert result.matched_agents == 0


def test_cross_layer_cloud_sql_requirement_reconciles_as_missing(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    infra = tmp_path / "infra"
    _write_app(app)
    _write_infra(infra)
    graph = Graph(agents=[Agent(name="shopright_assistant")])
    bundle = _bundle()

    enrich_cross_layer_required_authority(graph, app, infra, bundle)
    agent = authority_reconciliation_report(graph, bundle)["agents"][0]

    assert agent["required"]["roles"] == ["roles/cloudsql.client"]
    assert agent["missing"]["roles"] == ["roles/cloudsql.client"]
    assert agent["excess"]["roles"] == []
    assert agent["status"] == "missing_authority"
    assert "required_roles_incomplete" in agent["unresolved"]
    evidence = agent["evidence"]["required_authority"]
    assert evidence[0]["role"] == "roles/cloudsql.client"
