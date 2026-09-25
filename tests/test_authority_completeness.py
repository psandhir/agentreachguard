from pathlib import Path

from horustrace.authority_completeness import authority_completeness_report
from horustrace.deployment_evidence import (
    DeploymentEvidenceBundle,
    DeploymentWorkloadEvidence,
    IAMBindingEvidence,
)
from horustrace.deployment_report import build_deployment_security_report
from horustrace.models import Agent, Graph, Tool

IDENTITY = "agent@prod-project.iam.gserviceaccount.com"


def _bundle(role: str = "roles/discoveryengine.editor") -> DeploymentEvidenceBundle:
    return DeploymentEvidenceBundle(
        provider="gcp",
        source="test",
        workloads=(
            DeploymentWorkloadEvidence(
                workload_id="cloud-run://agent",
                kind="cloud_run",
                name="agent",
                identity=IDENTITY,
                agent="root_agent",
                project="prod-project",
            ),
        ),
        iam_bindings=(
            IAMBindingEvidence(
                principal=IDENTITY,
                role=role,
                scope_kind="project",
                scope_name="prod-project",
            ),
        ),
    )


def _write_source(root: Path, body: str) -> None:
    root.mkdir()
    (root / "agent.py").write_text(body, encoding="utf-8")


def test_discovery_absence_certificate_surfaces_candidate_excess_role(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    _write_source(
        app,
        """
from google.adk.agents import LlmAgent

root_agent = LlmAgent(name="root_agent", model="gemini-flash-latest")
""",
    )
    graph = Graph(agents=[Agent(name="root_agent")])

    report = authority_completeness_report(graph, _bundle(), app)

    assert report["enforcement"] == "measurement_only"
    assert report["summary"]["complete"] == 1
    assert report["summary"]["candidate_excess_roles_not_enforced"] == 1
    certificate = report["certificates"][0]
    assert certificate["state"] == "complete_absence"
    assert certificate["eligible_for_excess"] is True
    assert certificate["deployed_roles"] == ["roles/discoveryengine.editor"]
    assert certificate["required_roles"] == []
    assert certificate["candidate_excess_roles_not_enforced"] == [
        "roles/discoveryengine.editor"
    ]
    assert certificate["blockers"] == []


def test_discovery_source_marker_prevents_negative_certificate(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    _write_source(
        app,
        """
from google.cloud import discoveryengine_v1 as discoveryengine

client = discoveryengine.SearchServiceClient()
""",
    )
    graph = Graph(agents=[Agent(name="root_agent")])

    report = authority_completeness_report(graph, _bundle(), app)

    certificate = report["certificates"][0]
    assert certificate["complete"] is False
    assert "discoveryengine_usage_present" in certificate["blockers"]
    assert certificate["candidate_excess_roles_not_enforced"] == []
    assert certificate["family_markers"]


def test_dynamic_execution_prevents_negative_certificate(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    _write_source(
        app,
        """
import subprocess

def helper(command: str):
    return subprocess.run(command, shell=True)
""",
    )
    graph = Graph(agents=[Agent(name="root_agent")])

    report = authority_completeness_report(graph, _bundle(), app)

    certificate = report["certificates"][0]
    assert certificate["complete"] is False
    assert "dynamic_execution_surface" in certificate["blockers"]


def test_agent_execution_capability_prevents_negative_certificate(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    _write_source(app, "VALUE = 1\n")
    graph = Graph(
        agents=[
            Agent(
                name="root_agent",
                tools=[
                    Tool(
                        name="shell",
                        kind="function",
                        capabilities={"process.execute"},
                    )
                ],
            )
        ]
    )

    report = authority_completeness_report(graph, _bundle(), app)

    certificate = report["certificates"][0]
    assert certificate["complete"] is False
    assert "agent_dynamic_execution_capability" in certificate["blockers"]


def test_candidate_excess_role_is_not_enforced_by_reconciliation(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    _write_source(app, "VALUE = 1\n")
    graph = Graph(agents=[Agent(name="root_agent")])

    report = build_deployment_security_report(
        graph,
        _bundle(),
        source_root=app,
    )

    certificate = report["authority_completeness"]["certificates"][0]
    assert certificate["candidate_excess_roles_not_enforced"] == [
        "roles/discoveryengine.editor"
    ]
    assert report["summary"]["excess_authority_agents"] == 0
    reconciliation = report["reconciliation"]["agents"][0]
    assert reconciliation["excess"]["roles"] == []
    assert reconciliation["status"] == "unresolved"



def test_adc_project_lookup_alone_does_not_block_family_absence(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    _write_source(
        app,
        """
import google.auth

_, project_id = google.auth.default()
""",
    )
    graph = Graph(agents=[Agent(name="root_agent")])

    report = authority_completeness_report(graph, _bundle(), app)

    certificate = report["certificates"][0]
    assert certificate["complete"] is True
    assert certificate["candidate_excess_roles_not_enforced"] == [
        "roles/discoveryengine.editor"
    ]


def test_adc_plus_generic_http_blocks_family_absence(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    _write_source(
        app,
        """
import google.auth
import requests

credentials, project_id = google.auth.default()

def call_service(url: str):
    return requests.get(url)
""",
    )
    graph = Graph(agents=[Agent(name="root_agent")])

    report = authority_completeness_report(graph, _bundle(), app)

    certificate = report["certificates"][0]
    assert certificate["complete"] is False
    assert "generic_authenticated_google_api_surface" in certificate["blockers"]



def test_endpoint_marker_requires_discovery_engine_hostname(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    _write_source(
        app,
        """
VALUE = "https://discoveryengine.googleapis.com/v1/projects/demo"
""",
    )
    graph = Graph(agents=[Agent(name="root_agent")])

    report = authority_completeness_report(graph, _bundle(), app)

    certificate = report["certificates"][0]
    assert certificate["complete"] is False
    assert "discoveryengine_usage_present" in certificate["blockers"]
    assert any(
        item["kind"] == "endpoint"
        and item["marker"].startswith("https://discoveryengine.googleapis.com/")
        for item in certificate["family_markers"]
    )


def test_endpoint_text_in_unrelated_url_path_is_not_a_marker(
    tmp_path: Path,
) -> None:
    app = tmp_path / "app"
    _write_source(
        app,
        """
VALUE = "https://example.com/docs/discoveryengine.googleapis.com/reference"
""",
    )
    graph = Graph(agents=[Agent(name="root_agent")])

    report = authority_completeness_report(graph, _bundle(), app)

    certificate = report["certificates"][0]
    assert certificate["complete"] is True
    assert certificate["family_markers"] == []
