from pathlib import Path

from horustrace.scanner import scan


def _write(root: Path, path: str, text: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def test_repository_adk_infers_positive_gcp_role_requirements(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "helper.py",
        """
from google.cloud import bigquery
from google.cloud import discoveryengine_v1 as discoveryengine


def search_data(query: str):
    bq = bigquery.Client()
    rows = bq.query("SELECT * FROM dataset.table LIMIT 10").result()

    search = discoveryengine.SearchServiceClient()
    search.search(
        request=discoveryengine.SearchRequest(
            serving_config="projects/p/locations/global/collections/default_collection/"
            "engines/e/servingConfigs/default_search",
            query=query,
        )
    )
    return rows
""",
    )
    _write(
        tmp_path,
        "agent.py",
        """
from google.adk import Agent
from helper import search_data

root_agent = Agent(
    name="analyst",
    model="gemini-flash-latest",
    tools=[search_data],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "analyst")
    tool = next(item for item in agent.tools if item.name == "search_data")

    assert set(tool.metadata["required_roles"]) == {
        "roles/bigquery.dataViewer",
        "roles/bigquery.jobUser",
        "roles/discoveryengine.viewer",
    }
    assert tool.metadata["required_roles_complete"] is False
    evidence = tool.metadata["required_role_evidence"]
    assert any(item["operation"] == "bigquery.query" for item in evidence)
    assert any(
        item["operation"] == "discoveryengine.search"
        for item in evidence
    )


def test_repository_adk_infers_bigquery_insert_role(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "agent.py",
        """
from google.adk import Agent
from google.cloud import bigquery


def log_event(payload: dict):
    client = bigquery.Client()
    return client.insert_rows_json("project.dataset.events", [payload])


root_agent = Agent(
    name="logger",
    model="gemini-flash-latest",
    tools=[log_event],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "logger")
    tool = next(item for item in agent.tools if item.name == "log_event")

    assert tool.metadata["required_roles"] == ["roles/bigquery.dataEditor"]


def test_adk_bigquery_toolset_exposes_partial_role_requirements(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "agent.py",
        """
from google.adk import Agent
from google.adk.tools.bigquery import BigQueryToolset

bq = BigQueryToolset()
root_agent = Agent(
    name="analyst",
    model="gemini-flash-latest",
    tools=[bq],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "analyst")
    tool = next(item for item in agent.tools if item.name == "bq")

    assert set(tool.metadata["required_roles"]) == {
        "roles/bigquery.dataEditor",
        "roles/bigquery.dataViewer",
        "roles/bigquery.jobUser",
    }
    assert tool.metadata["required_roles_complete"] is False



def test_required_roles_follow_asyncio_to_thread_callback(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "agent.py",
        """
import asyncio
from google.adk import Agent
from google.cloud import discoveryengine_v1 as discoveryengine


def _rank_sync(query: str):
    client = discoveryengine.RankServiceClient()
    return client.rank(
        discoveryengine.RankRequest(
            ranking_config="projects/p/locations/global/rankingConfigs/default",
            query=query,
        )
    )


async def search(query: str):
    return await asyncio.to_thread(_rank_sync, query)


root_agent = Agent(
    name="searcher",
    model="gemini-flash-latest",
    tools=[search],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "searcher")
    tool = next(item for item in agent.tools if item.name == "search")

    assert tool.metadata["required_roles"] == [
        "roles/discoveryengine.viewer"
    ]


def test_required_roles_follow_explicit_agenttool_delegation(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "child.py",
        """
from google.adk import Agent
from google.cloud import bigquery


def run_query(question: str):
    client = bigquery.Client()
    return client.query("SELECT 1").result()


child_agent = Agent(
    name="database_agent",
    model="gemini-flash-latest",
    tools=[run_query],
)
""",
    )
    _write(
        tmp_path,
        "agent.py",
        """
from google.adk import Agent
from google.adk.tools.agent_tool import AgentTool
from child import child_agent


async def call_database(question: str, tool_context):
    delegate = AgentTool(agent=child_agent)
    return await delegate.run_async(
        args={"request": question},
        tool_context=tool_context,
    )


root_agent = Agent(
    name="coordinator",
    model="gemini-flash-latest",
    tools=[call_database],
)
""",
    )

    graph, _ = scan(tmp_path)
    agent = next(item for item in graph.agents if item.name == "coordinator")
    tool = next(item for item in agent.tools if item.name == "call_database")

    assert set(tool.metadata["required_roles"]) == {
        "roles/bigquery.dataViewer",
        "roles/bigquery.jobUser",
    }
