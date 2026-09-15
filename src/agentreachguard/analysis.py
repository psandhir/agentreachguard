from __future__ import annotations

from agentreachguard.heuristics import (
    HIGH_RISK_CAPABILITIES,
    SENSITIVE_CLASSES,
    UNTRUSTED_INPUT_KINDS,
)
from agentreachguard.models import AttackPath, Graph, Severity


def build_attack_paths(graph: Graph) -> list[AttackPath]:
    paths: list[AttackPath] = []

    for agent in graph.agents:
        untrusted = [i for i in agent.inputs if i.trust == "untrusted" or i.kind in UNTRUSTED_INPUT_KINDS]
        sensitive = [d for d in agent.data_sources if d.classification in SENSITIVE_CLASSES]
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
                        title="Untrusted input to command execution",
                        agent=agent.name,
                        nodes=[untrusted[0].name, agent.name, tool.name, "process.execute"],
                        severity=Severity.CRITICAL,
                        rationale="Untrusted content can influence an agent that can execute processes without approval.",
                        location=tool.location or agent.location,
                    )
                )

        for tool in destructive:
            if untrusted and tool.approval is not True:
                paths.append(
                    AttackPath(
                        path_id="PATH002",
                        title="Untrusted input to destructive action",
                        agent=agent.name,
                        nodes=[untrusted[0].name, agent.name, tool.name, "destructive.write"],
                        severity=Severity.HIGH,
                        rationale="Untrusted content can influence an agent that can perform destructive state changes.",
                        location=tool.location or agent.location,
                    )
                )

        for tool in outbound:
            if sensitive and tool.approval is not True:
                paths.append(
                    AttackPath(
                        path_id="PATH003",
                        title="Sensitive data to external destination",
                        agent=agent.name,
                        nodes=[sensitive[0].name, agent.name, tool.name, "external destination"],
                        severity=Severity.CRITICAL,
                        rationale="Sensitive data is reachable by an agent with an unapproved external write/egress capability.",
                        location=tool.location or agent.location,
                    )
                )

        if untrusted and sensitive and execution:
            paths.append(
                AttackPath(
                    path_id="PATH004",
                    title="Untrusted input, sensitive data and arbitrary execution",
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
                    title="Untrusted input to secret access and egress",
                    agent=agent.name,
                    nodes=[untrusted[0].name, agent.name, secret_tools[0].name, outbound[0].name],
                    severity=Severity.CRITICAL,
                    rationale="Untrusted input can reach secret-reading and outbound capabilities in the same agent.",
                    location=agent.location,
                )
            )

        privileged = sorted(agent.capabilities & HIGH_RISK_CAPABILITIES)
        if len(privileged) >= 2 and untrusted:
            paths.append(
                AttackPath(
                    path_id="PATH006",
                    title="Untrusted input reaches multiple high-risk capabilities",
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
        key = (path.path_id, path.agent, tuple(path.nodes))
        if key not in seen:
            seen.add(key)
            result.append(path)
    return result
