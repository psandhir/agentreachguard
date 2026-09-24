"""Generate reviewable Authority Contract proposals from observed effective authority."""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

import yaml

from horustrace.effective_authority import effective_authority_relationships
from horustrace.models import Graph

POLICY_PROPOSAL_SCHEMA_VERSION = 1

_SCOPE_KEYS = (
    "capabilities",
    "identities",
    "resources",
    "destinations",
    "iam_roles",
    "permissions",
    "oauth_scopes",
    "mcp_servers",
)


def build_authority_policy_proposal(graph: Graph) -> dict[str, Any]:
    """Build a deterministic, evidence-sensitive starting Authority Contract.

    The proposal constrains only values observed in effective-authority evidence.
    Unknown dimensions are reported as diagnostics and are never converted into
    permissive wildcard entries.
    """
    relationships = effective_authority_relationships(graph)
    by_agent: dict[str, list[Any]] = defaultdict(list)
    for relationship in relationships:
        by_agent[relationship.agent].append(relationship)

    agents: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []

    for agent in sorted(graph.agents, key=lambda item: item.name):
        scope = {key: set() for key in _SCOPE_KEYS}
        approval_required: set[str] = set()
        mcp_tools: dict[str, set[str]] = {}
        unresolved: set[str] = set()

        for relationship in by_agent.get(agent.name, []):
            scope["capabilities"].update(relationship.capabilities)

            identity = relationship.identity or {}
            if identity.get("name"):
                scope["identities"].add(str(identity["name"]))
            scope["iam_roles"].update(str(value) for value in identity.get("roles") or [])
            scope["permissions"].update(
                str(value) for value in identity.get("permissions") or []
            )
            scope["oauth_scopes"].update(
                str(value) for value in identity.get("oauth_scopes") or []
            )

            scope["resources"].update(
                str(item["selector"])
                for item in relationship.resources
                if item.get("selector")
            )
            scope["destinations"].update(
                str(item["target"])
                for item in relationship.destinations
                if item.get("target")
            )

            if relationship.target_kind == "mcp_server":
                scope["mcp_servers"].add(relationship.target_name)
                tool_scope = relationship.tool_scope or {}
                if tool_scope.get("scope") == "explicit_allowlist":
                    allowed = {
                        str(value) for value in tool_scope.get("allowed") or []
                    }
                    if allowed:
                        mcp_tools.setdefault(relationship.target_name, set()).update(allowed)

            if relationship.approval.get("required") is True:
                approval_required.update(relationship.capabilities)

            unresolved.update(relationship.unresolved)

        allow = {
            key: sorted(values)
            for key, values in scope.items()
            if values
        }
        authority: dict[str, Any] = {"allow": allow}
        if approval_required:
            authority["require_approval_for"] = sorted(approval_required)
        if mcp_tools:
            authority["mcp_tools"] = [
                {"server": server, "allow": sorted(tools)}
                for server, tools in sorted(mcp_tools.items())
            ]

        agents.append(
            {
                "name": agent.name,
                "policy": {
                    "authority": authority,
                },
            }
        )
        if unresolved:
            diagnostics.append(
                {
                    "agent": agent.name,
                    "unresolved_dimensions": sorted(unresolved),
                }
            )

    return {
        "schema_version": POLICY_PROPOSAL_SCHEMA_VERSION,
        "runtime_effectiveness": "not_verified",
        "manifest": {
            "version": 1,
            "agents": agents,
        },
        "diagnostics": diagnostics,
        "summary": {
            "agents": len(agents),
            "agents_with_unresolved_authority": len(diagnostics),
            "relationships_observed": len(relationships),
        },
    }


def render_authority_policy_yaml(report: dict[str, Any]) -> str:
    """Render only the valid manifest fragment so output can be reviewed or merged."""
    return yaml.safe_dump(
        report["manifest"],
        sort_keys=False,
        default_flow_style=False,
    ).rstrip()


def render_authority_policy_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2)
