"""Integrated v0.8 deployed-authority reconciliation report."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from horustrace.authority_completeness import authority_completeness_report
from horustrace.authority_reconciliation import authority_reconciliation_report
from horustrace.deployed_authority import deployed_authority_report
from horustrace.deployed_identity import deployed_identity_report
from horustrace.deployed_policy import deployed_policy_report
from horustrace.deployment_delta import deployment_authority_delta
from horustrace.deployment_evidence import DeploymentEvidenceBundle
from horustrace.models import Graph

DEPLOYMENT_SECURITY_REPORT_SCHEMA_VERSION = 1


def build_deployment_security_report(
    graph: Graph,
    bundle: DeploymentEvidenceBundle,
    *,
    baseline: DeploymentEvidenceBundle | None = None,
    source_root: Path | None = None,
) -> dict[str, Any]:
    identity = deployed_identity_report(graph, bundle)
    deployed = deployed_authority_report(graph, bundle)
    reconciliation = authority_reconciliation_report(graph, bundle)
    completeness = (
        authority_completeness_report(graph, bundle, source_root)
        if source_root is not None
        else None
    )
    policy = deployed_policy_report(graph, bundle)
    delta = (
        deployment_authority_delta(graph, baseline, bundle)
        if baseline is not None
        else None
    )

    excess_agents = sum(
        item["status"] in {"excess_authority", "mixed"}
        for item in reconciliation["agents"]
    )
    missing_agents = sum(
        item["status"] in {"missing_authority", "mixed"}
        for item in reconciliation["agents"]
    )
    unresolved_agents = sum(bool(item["unresolved"]) for item in reconciliation["agents"])
    policy_violations = policy["summary"]["violation"]
    policy_unresolved = policy["summary"]["unresolved"]
    regressed_agents = delta["summary"]["regressed_agents"] if delta else 0

    return {
        "schema_version": DEPLOYMENT_SECURITY_REPORT_SCHEMA_VERSION,
        "provider": bundle.provider,
        "evidence_source": bundle.source,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "agents": reconciliation["summary"]["agents"],
            "deployed_identity_relationships": identity["summary"]["relationships"],
            "deployed_authority_relationships": deployed["summary"]["relationships"],
            "excess_authority_agents": excess_agents,
            "missing_authority_agents": missing_agents,
            "unresolved_agents": unresolved_agents,
            "deployed_policy_violations": policy_violations,
            "deployed_policy_unresolved": policy_unresolved,
            "deployment_regressed_agents": regressed_agents,
        },
        "deployed_identity": identity,
        "deployed_authority": deployed,
        "reconciliation": reconciliation,
        "authority_completeness": completeness,
        "deployed_policy": policy,
        "deployment_delta": delta,
    }


def render_deployment_security_console(
    report: dict[str, Any],
    root: Path,
) -> str:
    summary = report["summary"]
    lines = [
        "HorusTrace Deployed Authority Reconciliation",
        "=" * 42,
        f"Target:                         {root}",
        f"Provider:                       {report['provider']}",
        f"Evidence source:                {report['evidence_source']}",
        f"Agents:                         {summary['agents']}",
        f"Deployment identity mappings:   {summary['deployed_identity_relationships']}",
        f"Deployed authority mappings:    {summary['deployed_authority_relationships']}",
        f"Agents with excess authority:   {summary['excess_authority_agents']}",
        f"Agents with missing authority:  {summary['missing_authority_agents']}",
        f"Agents with unresolved state:   {summary['unresolved_agents']}",
        f"Deployed policy violations:     {summary['deployed_policy_violations']}",
        f"Deployment regressions:         {summary['deployment_regressed_agents']}",
        "Runtime effectiveness:          NOT VERIFIED",
        "",
    ]

    completeness = report.get("authority_completeness")
    if isinstance(completeness, dict):
        completeness_summary = completeness.get("summary") or {}
        lines.extend(
            [
                "Authority completeness (measurement only)",
                "-" * 41,
                (
                    "Complete family certificates:    "
                    f"{completeness_summary.get('complete', 0)}"
                ),
                (
                    "Incomplete family certificates:  "
                    f"{completeness_summary.get('incomplete', 0)}"
                ),
                (
                    "Candidate excess roles:           "
                    f"{completeness_summary.get('candidate_excess_roles_not_enforced', 0)} "
                    "(NOT ENFORCED)"
                ),
                "",
            ]
        )

    policy_by_agent = {
        item["agent"]: item
        for item in report["deployed_policy"]["relationships"]
    }
    for item in report["reconciliation"]["agents"]:
        lines.append(f"{item['agent']}  [{item['status'].upper()}]")
        required = item["required"]
        deployed = item["deployed"]
        excess = item["excess"]
        missing = item["missing"]
        lines.append(
            "  required roles: "
            + (", ".join(required["roles"]) if required["roles"] else "unknown")
        )
        lines.append(
            "  deployed roles: "
            + (", ".join(deployed["roles"]) if deployed["roles"] else "none")
        )
        if excess["roles"] or excess["permissions"]:
            lines.append(
                "  excess: roles="
                + (", ".join(excess["roles"]) or "none")
                + "; permissions="
                + (", ".join(excess["permissions"]) or "none")
            )
        if missing["roles"] or missing["permissions"]:
            lines.append(
                "  missing: roles="
                + (", ".join(missing["roles"]) or "none")
                + "; permissions="
                + (", ".join(missing["permissions"]) or "none")
            )
        if deployed.get("conditional_roles"):
            lines.append(
                "  conditional roles: "
                + ", ".join(deployed["conditional_roles"])
            )
        if deployed["conditional_permissions"]:
            lines.append(
                "  conditional permissions: "
                + ", ".join(deployed["conditional_permissions"])
            )
        lines.append(
            "  unresolved: "
            + (", ".join(item["unresolved"]) if item["unresolved"] else "none")
        )
        policy = policy_by_agent.get(item["agent"])
        if policy is not None:
            lines.append(f"  deployed policy: {policy['status']}")
        lines.append("")

    delta = report.get("deployment_delta")
    if delta is not None:
        lines.extend(
            [
                "Deployment drift",
                "-" * 16,
                f"Changed agents:                  {delta['summary']['changed_agents']}",
                f"Regressed agents:                {delta['summary']['regressed_agents']}",
                f"Introduced excess roles:         {delta['summary']['introduced_excess_roles']}",
                f"Introduced excess permissions:   {delta['summary']['introduced_excess_permissions']}",
                f"Introduced conditional roles:    {delta['summary'].get('introduced_conditional_roles', 0)}",
                f"Introduced conditional perms:    {delta['summary'].get('introduced_conditional_permissions', 0)}",
                "",
            ]
        )
        for item in delta["agents"]:
            if not item["regressed"] and not item["improved"]:
                continue
            lines.append(
                f"{item['agent']}: regressed={item['regressed']} improved={item['improved']}"
            )
            if item["excess"]["roles_introduced"]:
                lines.append(
                    "  excess roles introduced: "
                    + ", ".join(item["excess"]["roles_introduced"])
                )
            if item["excess"]["permissions_introduced"]:
                lines.append(
                    "  excess permissions introduced: "
                    + ", ".join(item["excess"]["permissions_introduced"])
                )
            conditional = item.get("conditional") or {}
            if conditional.get("roles_added"):
                lines.append(
                    "  conditional roles added: "
                    + ", ".join(conditional["roles_added"])
                )
            if conditional.get("permissions_added"):
                lines.append(
                    "  conditional permissions added: "
                    + ", ".join(conditional["permissions_added"])
                )
            if item["trust_boundary_crossings"]:
                lines.append(
                    "  trust boundaries: "
                    + ", ".join(item["trust_boundary_crossings"])
                )
            lines.append("")

    return "\n".join(lines).rstrip()
