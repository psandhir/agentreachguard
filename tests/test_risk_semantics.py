from horustrace.models import Graph, NetworkDestination, Tool
from horustrace.semantics import annotate_risk_semantics


def test_risk_semantics_distinguish_mutation_types() -> None:
    graph = Graph(
        unbound_tools=[
            Tool(name="update_session_context", kind="function", capabilities={"data.write"}),
            Tool(name="redis_store", kind="function", capabilities={"data.write"}),
            Tool(name="delete_account", kind="function", capabilities={"data.write", "destructive.write"}),
            Tool(
                name="publish_message",
                kind="function",
                capabilities={"external.write", "network.external"},
            ),
        ]
    )

    annotate_risk_semantics(graph)

    by_name = {tool.name: tool for tool in graph.all_tools()}
    assert by_name["update_session_context"].metadata["mutation_semantics"] == "local_session_state_write"
    assert by_name["redis_store"].metadata["mutation_semantics"] == "persistent_internal_write"
    assert by_name["delete_account"].metadata["mutation_semantics"] == "destructive_write"
    assert by_name["delete_account"].metadata["sensitive_write_domain"] == "financial_identity_or_security"
    assert by_name["publish_message"].metadata["mutation_semantics"] == "external_side_effect"
    assert by_name["publish_message"].metadata["network_semantics"] == "arbitrary_egress"


def test_risk_semantics_distinguish_fixed_provider_from_arbitrary_network() -> None:
    graph = Graph(
        unbound_tools=[
            Tool(
                name="google_search",
                kind="search",
                capabilities={"data.read", "network.external"},
                metadata={"network_scope": "fixed_managed_service"},
            ),
            Tool(
                name="read_api",
                kind="function",
                capabilities={"data.read", "network.external"},
                destinations=[
                    NetworkDestination(
                        target="https://api.example.com",
                        restricted=True,
                    )
                ],
            ),
            Tool(
                name="search_web",
                kind="function",
                capabilities={"data.read", "network.external"},
            ),
        ]
    )

    annotate_risk_semantics(graph)

    by_name = {tool.name: tool for tool in graph.all_tools()}
    assert by_name["google_search"].metadata["network_semantics"] == "fixed_provider_network"
    assert by_name["read_api"].metadata["network_semantics"] == "fixed_provider_network"
    assert by_name["search_web"].metadata["network_semantics"] == "arbitrary_internet_retrieval"
