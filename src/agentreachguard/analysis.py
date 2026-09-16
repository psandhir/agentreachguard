from __future__ import annotations

from agentreachguard.heuristics import (
    HIGH_RISK_CAPABILITIES,
    UNTRUSTED_INPUT_KINDS,
)
from agentreachguard.models import AttackPath, Graph, Severity


def build_attack_paths(graph: Graph) -> list[AttackPath]:
    paths: list[AttackPath] = []

    for agent in graph.agents:
        untrusted = [i for i in agent.inputs if i.trust == "untrusted" or i.kind in UNTRUSTED_INPUT_KINDS]
        sensitive = agent.sensitive_data_sources
        outbound = [
            t for t in agent.tools if {"network.external", "external.write"} & t.capabilities
        ]
        execution = [t for t in agent.tools if "process.execute" in t.capabilities]
        destructive = [t for t in agent.tools if "destructive.write" in t.capabilities]
        secret_tools = [t for t in agent.tools if "secrets.read" in t.capabilities]

        for tool in execution:
            if untrusted and tool.approval is not True:
                paths.append(
                    AttackPath(
                        path_id="PATH001",
                        title="Potential untrusted-input path to command execution",
                        agent=agent.name,
                        nodes=[untrusted[0].name, agent.name, tool.name, "process.execute"],
                        severity=Severity.CRITICAL,
                        rationale="The normalized agent model combines untrusted input and process-execution capability without a detected approval requirement.",
                        location=tool.location or agent.location,
                    )
                )

        for tool in destructive:
            if untrusted and tool.approval is not True:
                paths.append(
                    AttackPath(
                        path_id="PATH002",
                        title="Potential untrusted-input path to destructive action",
                        agent=agent.name,
                        nodes=[untrusted[0].name, agent.name, tool.name, "destructive.write"],
                        severity=Severity.HIGH,
                        rationale="The normalized agent model combines untrusted input and destructive-write capability without a detected approval requirement.",
                        location=tool.location or agent.location,
                    )
                )

        for tool in outbound:
            if sensitive and tool.approval is not True:
                paths.append(
                    AttackPath(
                        path_id="PATH003",
                        title="Potential sensitive-data path to an external destination",
                        agent=agent.name,
                        nodes=[sensitive[0].name, agent.name, tool.name, "external destination"],
                        severity=Severity.CRITICAL,
                        rationale="The normalized agent model combines sensitive-data access and external write/egress capability without a detected approval requirement.",
                        location=tool.location or agent.location,
                    )
                )

        if untrusted and sensitive and execution:
            paths.append(
                AttackPath(
                    path_id="PATH004",
                    title="Potential combination of untrusted input, sensitive data and execution",
                    agent=agent.name,
                    nodes=[untrusted[0].name, agent.name, sensitive[0].name, execution[0].name],
                    severity=Severity.CRITICAL,
                    rationale="The agent combines untrusted input, sensitive data access and arbitrary process execution.",
                    location=agent.location,
                )
            )

        if untrusted and secret_tools and outbound:
            paths.append(
                AttackPath(
                    path_id="PATH005",
                    title="Potential untrusted-input path to secret access and egress",
                    agent=agent.name,
                    nodes=[untrusted[0].name, agent.name, secret_tools[0].name, outbound[0].name],
                    severity=Severity.CRITICAL,
                    rationale="The normalized agent model combines untrusted input, secret-reading capability and outbound capability.",
                    location=agent.location,
                )
            )

        privileged = sorted(agent.capabilities & HIGH_RISK_CAPABILITIES)
        if len(privileged) >= 2 and untrusted:
            paths.append(
                AttackPath(
                    path_id="PATH006",
                    title="Potential untrusted-input exposure to multiple high-risk capabilities",
                    agent=agent.name,
                    nodes=[untrusted[0].name, agent.name, *privileged],
                    severity=Severity.HIGH,
                    rationale="The same agent combines untrusted input with multiple high-risk capabilities.",
                    location=agent.location,
                )
            )

    # De-duplicate paths with identical IDs/agents/nodes.
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    result: list[AttackPath] = []
    for path in paths:
        path.metadata.update({
            "assessment": "potential_risk", "basis": "capability_cooccurrence",
            "exploitability": "not_verified",
            "limitations": [
                "The scanner does not establish executable data flow between these nodes.",
                "Runtime authorization and control effectiveness are not verified.",
            ],
        })
        key = (path.path_id, path.agent, tuple(path.nodes))
        if key not in seen:
            seen.add(key)
            result.append(path)
    return result
