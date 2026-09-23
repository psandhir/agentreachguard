#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

from horustrace.config import load_config
from horustrace.scanner import scan


def _relative(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    parser.add_argument("--output", type=Path, default=Path("fast-agent-validation.json"))
    args = parser.parse_args()

    root = args.target.resolve()
    graph, findings = scan(root, config=load_config(root))

    fast_agents = [
        agent for agent in graph.agents
        if agent.metadata.get("framework") == "fast-agent"
    ]

    agent_types = collections.Counter(
        str(agent.metadata.get("agent_type") or "unknown")
        for agent in fast_agents
    )
    flow_contexts = collections.Counter(
        flow.execution_context.value for flow in graph.flow_paths
    )
    reachability = collections.Counter(
        flow.agent_reachability.value for flow in graph.flow_paths
    )
    diagnostics = collections.Counter(
        diagnostic.kind or diagnostic.code
        for diagnostic in graph.coverage.diagnostics
    )
    finding_rules = collections.Counter(finding.rule_id for finding in findings)

    agents = []
    for agent in fast_agents:
        agents.append(
            {
                "name": agent.name,
                "path": _relative(
                    agent.location.path if agent.location else None,
                    root,
                ),
                "line": agent.location.line if agent.location else None,
                "agent_type": agent.metadata.get("agent_type"),
                "app_name": agent.metadata.get("app_name"),
                "decorated_function": agent.metadata.get("decorated_function"),
                "delegates_to": list(agent.metadata.get("delegates_to") or []),
                "mcp_server_refs": list(agent.metadata.get("mcp_server_refs") or []),
                "tools": [
                    {
                        "name": tool.name,
                        "kind": tool.kind,
                        "capabilities": sorted(tool.capabilities),
                        "source": tool.metadata.get("source"),
                        "source_function_key": tool.metadata.get("source_function_key"),
                    }
                    for tool in agent.tools
                ],
            }
        )

    report = {
        "target": str(root),
        "summary": {
            "agents_total": len(graph.agents),
            "fast_agent_agents": len(fast_agents),
            "tools_total": len(graph.all_tools()),
            "unbound_tools": len(graph.unbound_tools),
            "mcp_servers": len(graph.all_mcp_servers()),
            "flows": len(graph.flow_paths),
            "findings": len(findings),
            "coverage_incomplete": graph.coverage.incomplete,
            "adg_nodes": len(graph.adg.nodes) if graph.adg else 0,
            "adg_edges": len(graph.adg.edges) if graph.adg else 0,
            "delegation_edges": (
                sum(edge.kind == "DELEGATES_TO" for edge in graph.adg.edges)
                if graph.adg
                else 0
            ),
        },
        "agent_types": dict(agent_types),
        "flow_execution_contexts": dict(flow_contexts),
        "flow_agent_reachability": dict(reachability),
        "coverage_diagnostics": dict(diagnostics),
        "finding_rules": dict(finding_rules),
        "agents": agents,
        "flows": [flow.as_dict() for flow in graph.flow_paths],
    }

    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    print("agent_types=" + json.dumps(dict(agent_types), sort_keys=True))
    print("flow_execution_contexts=" + json.dumps(dict(flow_contexts), sort_keys=True))
    print("flow_agent_reachability=" + json.dumps(dict(reachability), sort_keys=True))
    print("coverage_diagnostics=" + json.dumps(dict(diagnostics), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
