#!/usr/bin/env python3
"""Re-scan a frozen public corpus with the current HorusTrace checkout.

Target repositories are fetched at exact commit SHAs and are never imported,
installed, or executed. Each scan runs in a child process with a hard timeout.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CLONE_TIMEOUT = 180
SCAN_TIMEOUT = 300
PREFLIGHT_MAX_BYTES = 2_000_000
TEXT_SUFFIXES = {".py", ".json", ".yaml", ".yml", ".toml", ".ipynb", ".md"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}

CATEGORY_MARKERS = {
    "google-adk": ("google.adk", "google_adk"),
    "openai-agents": (
        "from agents ",
        "from agents.",
        "import agents",
        "agents.mcp",
        "openai-agents",
    ),
    "langgraph": ("langgraph", "stategraph", "messagegraph"),
    "mcp-mixed": ("modelcontextprotocol", "fastmcp", "mcpserver", "mcp_server", "mcp."),
}


def run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        command,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def fetch_frozen_repo(root: Path, repo: str, sha: str) -> tuple[Path, str | None]:
    target = root / repo.replace("/", "__")
    target.mkdir(parents=True, exist_ok=True)
    commands = [
        ["git", "init", "-q", str(target)],
        ["git", "-C", str(target), "remote", "add", "origin", f"https://github.com/{repo}.git"],
        [
            "git", "-C", str(target), "fetch", "--quiet", "--depth=1",
            "--filter=blob:none", "origin", sha,
        ],
        ["git", "-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
    ]
    for command in commands:
        result = run(command, timeout=CLONE_TIMEOUT)
        if result.returncode != 0:
            return target, (result.stderr or result.stdout).strip()[-3000:]
    rev = run(["git", "-C", str(target), "rev-parse", "HEAD"], timeout=30)
    if rev.returncode != 0:
        return target, (rev.stderr or rev.stdout).strip()[-3000:]
    resolved = rev.stdout.strip()
    if resolved != sha:
        return target, f"frozen SHA mismatch: expected {sha}, got {resolved}"
    return target, None


def preflight(target: Path, category: str) -> dict:
    python_files = 0
    text_files = 0
    marker_files: list[str] = []
    markers = CATEGORY_MARKERS[category]
    for path in target.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            if path.stat().st_size > PREFLIGHT_MAX_BYTES:
                continue
        except OSError:
            continue
        text_files += 1
        if path.suffix.lower() == ".py":
            python_files += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        if any(marker in text for marker in markers):
            try:
                marker_files.append(path.relative_to(target).as_posix())
            except ValueError:
                marker_files.append(path.as_posix())
    return {
        "python_files": python_files,
        "text_files_considered": text_files,
        "framework_marker_files": len(marker_files),
        "framework_marker_samples": marker_files[:20],
        "material": python_files > 0 and bool(marker_files),
    }


def _relative(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def scan_target(target: Path) -> dict:
    from horustrace import __version__
    from horustrace.config import load_config
    from horustrace.owasp import build_owasp_agentic_summary
    from horustrace.scanner import scan

    config = load_config(target)
    graph, findings = scan(target, config=config)
    adg = graph.adg.as_dict() if graph.adg else {"nodes": [], "edges": [], "summary": {}}
    node_kinds = {node["id"]: node["kind"] for node in adg.get("nodes", [])}
    mcp_nodes = {node_id for node_id, kind in node_kinds.items() if kind == "mcp_server"}
    agent_nodes = {node_id for node_id, kind in node_kinds.items() if kind == "agent"}
    identity_nodes = {node_id for node_id, kind in node_kinds.items() if kind == "identity"}
    approval_nodes = {
        node_id for node_id, kind in node_kinds.items() if kind == "approval_control"
    }

    mcp_agent_invokes = 0
    mcp_identity_edges = 0
    approval_guarded_edges = 0
    for edge in adg.get("edges", []):
        if (
            edge["kind"] == "INVOKES"
            and edge["source"] in agent_nodes
            and edge["target"] in mcp_nodes
        ):
            mcp_agent_invokes += 1
        if (
            edge["kind"] == "USES_IDENTITY"
            and edge["source"] in mcp_nodes
            and edge["target"] in identity_nodes
        ):
            mcp_identity_edges += 1
        if edge["kind"] == "GUARDED_BY" and edge["target"] in approval_nodes:
            approval_guarded_edges += 1

    tools = graph.all_tools()
    findings_by_context: collections.Counter[str] = collections.Counter()
    rules: collections.Counter[str] = collections.Counter()
    severities: collections.Counter[str] = collections.Counter()
    rules_by_context: dict[str, collections.Counter[str]] = {}
    finding_details: list[dict] = []
    for finding in findings:
        context = finding.source_context or "unknown"
        findings_by_context[context] += 1
        rules[finding.rule_id] += 1
        severities[finding.severity.label()] += 1
        rules_by_context.setdefault(context, collections.Counter())[finding.rule_id] += 1
        finding_details.append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.label(),
                "title": finding.title,
                "agent": finding.agent,
                "source_context": context,
                "path": _relative(finding.location.path, target) if finding.location else None,
                "line": finding.location.line if finding.location else None,
                "evidence": list(finding.evidence),
            }
        )

    diagnostics = collections.Counter(
        diagnostic.kind or diagnostic.code for diagnostic in graph.coverage.diagnostics
    )
    approval_mechanisms = collections.Counter(
        str(tool.metadata.get("approval_mechanism"))
        for tool in tools
        if tool.metadata.get("approval_mechanism")
    )
    mutation_semantics = collections.Counter(
        str(tool.metadata.get("mutation_semantics"))
        for tool in tools
        if tool.metadata.get("mutation_semantics")
    )
    network_semantics = collections.Counter(
        str(tool.metadata.get("network_semantics"))
        for tool in tools
        if tool.metadata.get("network_semantics")
    )
    attack_basis = collections.Counter(
        str(path.metadata.get("basis") or "capability_cooccurrence")
        for path in graph.attack_paths
    )
    flow_pairs = collections.Counter(
        f"{flow.source_kind}->{flow.sink_kind}" for flow in graph.flow_paths
    )
    flow_execution_contexts = collections.Counter(
        flow.execution_context.value for flow in graph.flow_paths
    )
    flow_agent_reachability = collections.Counter(
        flow.agent_reachability.value for flow in graph.flow_paths
    )
    flow_resolution = (graph.coverage.resolution or {}).get("flows", {})

    return {
        "scanner_version": __version__,
        "coverage_incomplete": graph.coverage.incomplete,
        "coverage_resolution": graph.coverage.resolution,
        "agents": len(graph.agents),
        "tools": len(tools),
        "mcp_servers": len(graph.all_mcp_servers()),
        "identities": len(graph.all_identities()),
        "flow_paths": len(graph.flow_paths),
        "agent_mapped_flows": sum(flow.agent is not None for flow in graph.flow_paths),
        "proven_agent_reachable_flows": flow_agent_reachability.get(
            "proven_agent_reachable",
            0,
        ),
        "proven_non_agent_flows": flow_agent_reachability.get(
            "proven_non_agent",
            0,
        ),
        "unknown_agent_reachability_flows": flow_agent_reachability.get(
            "unknown",
            0,
        ),
        "agent_attribution_gaps": int(
            flow_resolution.get("agent_attribution_gaps", 0) or 0
        ),
        "flow_execution_contexts": dict(flow_execution_contexts),
        "flow_agent_reachability": dict(flow_agent_reachability),
        "flow_pairs": dict(flow_pairs),
        "attack_paths": len(graph.attack_paths),
        "static_dataflow_attack_paths": attack_basis.get("static_dataflow", 0),
        "attack_path_basis": dict(attack_basis),
        "adg_nodes": len(adg.get("nodes", [])),
        "adg_edges": len(adg.get("edges", [])),
        "adg_node_kinds": (adg.get("summary") or {}).get("node_kinds", {}),
        "adg_edge_kinds": (adg.get("summary") or {}).get("edge_kinds", {}),
        "bound_mcp_references": sum(len(agent.mcp_servers) for agent in graph.agents),
        "unbound_mcp_references": len(graph.unbound_mcp_servers),
        "mcp_agent_invokes": mcp_agent_invokes,
        "mcp_identity_edges": mcp_identity_edges,
        "approval_control_nodes": len(approval_nodes),
        "approval_guarded_edges": approval_guarded_edges,
        "approved_tools": sum(tool.approval is True for tool in tools),
        "guarded_tools": sum(bool(tool.guardrails) for tool in tools),
        "approval_mechanisms": dict(approval_mechanisms),
        "mutation_semantics": dict(mutation_semantics),
        "network_semantics": dict(network_semantics),
        "findings": len(findings),
        "severities": dict(severities),
        "rules": dict(rules),
        "finding_source_contexts": dict(findings_by_context),
        "rules_by_source_context": {
            context: dict(counter) for context, counter in rules_by_context.items()
        },
        "finding_details": finding_details,
        "owasp_agentic": build_owasp_agentic_summary(findings),
        "diagnostics": dict(diagnostics),
    }


def scan_repo(root: Path, entry: dict) -> dict:
    started = time.monotonic()
    result = {
        "tier": entry["tier"],
        "category": entry["category"],
        "repo": entry["repo"],
        "branch": entry.get("branch"),
        "commit": entry["sha"],
        "clone": "failed",
        "scan": "not_run",
    }
    try:
        target, error = fetch_frozen_repo(root, entry["repo"], entry["sha"])
    except subprocess.TimeoutExpired:
        result["clone"] = "timeout"
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        return result

    if error:
        result["clone_error"] = error
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(target, ignore_errors=True)
        return result

    result["clone"] = "ok"
    result["preflight"] = preflight(target, entry["category"])
    try:
        child = run(
            [sys.executable, str(Path(__file__).resolve()), "--scan-target", str(target)],
            timeout=SCAN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        result["scan"] = "timeout"
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(target, ignore_errors=True)
        return result

    if child.returncode != 0:
        result["scan"] = "error"
        result["scan_error"] = (child.stderr or child.stdout).strip()[-5000:]
    else:
        try:
            result.update(json.loads(child.stdout))
            result["scan"] = "ok"
        except json.JSONDecodeError:
            result["scan"] = "invalid_json"
            result["scan_error"] = child.stdout.strip()[-5000:]

    result["elapsed_seconds"] = round(time.monotonic() - started, 2)
    shutil.rmtree(target, ignore_errors=True)
    return result


def _merge_counter(results: list[dict], field: str) -> dict[str, int]:
    counter: collections.Counter[str] = collections.Counter()
    for item in results:
        counter.update(item.get(field, {}) or {})
    return dict(counter)


def _aggregate_owasp(results: list[dict]) -> dict:
    categories: dict[str, dict] = {}
    mapped_findings = 0
    runtime_mapped_findings = 0
    for item in results:
        report = item.get("owasp_agentic") or {}
        summary = report.get("summary") or {}
        mapped_findings += int(summary.get("mapped_findings", 0) or 0)
        runtime_mapped_findings += int(summary.get("runtime_mapped_findings", 0) or 0)
        for category in report.get("categories", []):
            risk_id = category["id"]
            aggregate = categories.setdefault(
                risk_id,
                {
                    "id": risk_id,
                    "title": category["title"],
                    "mapped_rules": category.get("mapped_rules", []),
                    "finding_count": 0,
                    "runtime_finding_count": 0,
                    "non_runtime_finding_count": 0,
                    "unknown_source_context_finding_count": 0,
                    "source_contexts": collections.Counter(),
                    "affected_repositories": [],
                    "runtime_affected_repositories": [],
                    "finding_rule_ids": set(),
                    "runtime_finding_rule_ids": set(),
                },
            )
            aggregate["finding_count"] += int(category.get("finding_count", 0) or 0)
            aggregate["runtime_finding_count"] += int(
                category.get("runtime_finding_count", 0) or 0
            )
            aggregate["non_runtime_finding_count"] += int(
                category.get("non_runtime_finding_count", 0) or 0
            )
            aggregate["unknown_source_context_finding_count"] += int(
                category.get("unknown_source_context_finding_count", 0) or 0
            )
            aggregate["source_contexts"].update(category.get("source_contexts", {}) or {})
            aggregate["finding_rule_ids"].update(category.get("finding_rule_ids", []))
            aggregate["runtime_finding_rule_ids"].update(
                category.get("runtime_finding_rule_ids", [])
            )
            if category.get("finding_count", 0):
                aggregate["affected_repositories"].append(item["repo"])
            if category.get("runtime_finding_count", 0):
                aggregate["runtime_affected_repositories"].append(item["repo"])

    ordered = []
    for risk_id in sorted(categories):
        category = categories[risk_id]
        category["source_contexts"] = dict(category["source_contexts"])
        category["affected_repositories"] = sorted(set(category["affected_repositories"]))
        category["runtime_affected_repositories"] = sorted(
            set(category["runtime_affected_repositories"])
        )
        category["affected_repository_count"] = len(category["affected_repositories"])
        category["runtime_affected_repository_count"] = len(
            category["runtime_affected_repositories"]
        )
        category["finding_rule_ids"] = sorted(category["finding_rule_ids"])
        category["runtime_finding_rule_ids"] = sorted(
            category["runtime_finding_rule_ids"]
        )
        ordered.append(category)

    return {
        "mapped_findings": mapped_findings,
        "runtime_mapped_findings": runtime_mapped_findings,
        "categories": ordered,
    }


def build_summary(results: list[dict]) -> dict:
    scanned = [item for item in results if item.get("scan") == "ok"]
    numeric = [
        "agents", "tools", "mcp_servers", "identities", "flow_paths",
        "agent_mapped_flows", "proven_agent_reachable_flows",
        "proven_non_agent_flows", "unknown_agent_reachability_flows",
        "agent_attribution_gaps", "attack_paths", "static_dataflow_attack_paths",
        "adg_nodes", "adg_edges", "bound_mcp_references", "unbound_mcp_references",
        "mcp_agent_invokes", "mcp_identity_edges", "approval_control_nodes",
        "approval_guarded_edges", "approved_tools", "guarded_tools", "findings",
    ]
    return {
        "requested": len(results),
        "preflight_material": sum(bool(item.get("preflight", {}).get("material")) for item in results),
        "cloned": sum(item.get("clone") == "ok" for item in results),
        "scanned": len(scanned),
        "complete": sum(not item.get("coverage_incomplete", False) for item in scanned),
        "incomplete": sum(bool(item.get("coverage_incomplete")) for item in scanned),
        "scan_errors": sum(item.get("scan") == "error" for item in results),
        "scan_timeouts": sum(item.get("scan") == "timeout" for item in results),
        "clone_failures": sum(item.get("clone") == "failed" for item in results),
        "clone_timeouts": sum(item.get("clone") == "timeout" for item in results),
        "totals": {key: sum(int(item.get(key, 0) or 0) for item in scanned) for key in numeric},
        "severities": _merge_counter(scanned, "severities"),
        "rules": _merge_counter(scanned, "rules"),
        "finding_source_contexts": _merge_counter(scanned, "finding_source_contexts"),
        "diagnostics": _merge_counter(scanned, "diagnostics"),
        "approval_mechanisms": _merge_counter(scanned, "approval_mechanisms"),
        "mutation_semantics": _merge_counter(scanned, "mutation_semantics"),
        "network_semantics": _merge_counter(scanned, "network_semantics"),
        "attack_path_basis": _merge_counter(scanned, "attack_path_basis"),
        "flow_pairs": _merge_counter(scanned, "flow_pairs"),
        "flow_execution_contexts": _merge_counter(
            scanned,
            "flow_execution_contexts",
        ),
        "flow_agent_reachability": _merge_counter(
            scanned,
            "flow_agent_reachability",
        ),
        "owasp_agentic": _aggregate_owasp(scanned),
    }


def render_markdown(report: dict) -> str:
    summary = report["summary"]
    totals = summary["totals"]
    contexts = summary["finding_source_contexts"]
    runtime = int(contexts.get("runtime", 0))
    nonruntime = sum(int(value) for key, value in contexts.items() if key != "runtime")
    lines = [
        f"# HorusTrace frozen corpus rescan — Cohort {report['cohort'].upper()}",
        "",
        f"- Scanner commit: {report['scanner_commit']}",
        f"- Repositories: {summary['scanned']}/{summary['requested']} scanned",
        f"- Coverage complete/incomplete: {summary['complete']}/{summary['incomplete']}",
        f"- Errors/timeouts: {summary['scan_errors']}/{summary['scan_timeouts']}",
        (
            f"- Flows: {totals['flow_paths']} total; "
            f"agent-reachable={totals['proven_agent_reachable_flows']}; "
            f"proven-non-agent={totals['proven_non_agent_flows']}; "
            f"unknown={totals['unknown_agent_reachability_flows']}; "
            f"attribution-gaps={totals['agent_attribution_gaps']}"
        ),
        f"- Static-dataflow attack paths: {totals['static_dataflow_attack_paths']}",
        f"- MCP references: {totals['bound_mcp_references']} bound / {totals['unbound_mcp_references']} unbound",
        f"- ADG agent→MCP invokes: {totals['mcp_agent_invokes']}",
        f"- Approval-control nodes: {totals['approval_control_nodes']}",
        f"- Findings: {totals['findings']} total; runtime={runtime}; non-runtime={nonruntime}",
        "",
        "## Per repository",
        "",
        "| Repository | Scan | Incomplete | Agents | MCP | Bound MCP | Flows | Agent | Non-agent | Unknown | Gaps | Static paths | Findings | Seconds |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in report["results"]:
        contexts = item.get("finding_source_contexts", {}) or {}
        lines.append(
            "| {repo} | {scan} | {incomplete} | {agents} | {mcp} | {bound} | {flows} | "
            "{agent_reachable} | {non_agent} | {unknown} | {gaps} | "
            "{static_paths} | {findings} | {seconds} |".format(
                repo=item["repo"],
                scan=item.get("scan"),
                incomplete="yes" if item.get("coverage_incomplete") else "no",
                agents=item.get("agents", "-"),
                mcp=item.get("mcp_servers", "-"),
                bound=item.get("bound_mcp_references", "-"),
                flows=item.get("flow_paths", "-"),
                agent_reachable=item.get("proven_agent_reachable_flows", "-"),
                non_agent=item.get("proven_non_agent_flows", "-"),
                unknown=item.get("unknown_agent_reachability_flows", "-"),
                gaps=item.get("agent_attribution_gaps", "-"),
                static_paths=item.get("static_dataflow_attack_paths", "-"),
                findings=item.get("findings", "-"),
                seconds=item.get("elapsed_seconds", "-"),
            )
        )
    lines += ["", "## Flow execution contexts", ""]
    for key, value in sorted(summary["flow_execution_contexts"].items()):
        lines.append(f"- {key}: {value}")
    if not summary["flow_execution_contexts"]:
        lines.append("- none")

    lines += ["", "## Agent reachability", ""]
    for key, value in sorted(summary["flow_agent_reachability"].items()):
        lines.append(f"- {key}: {value}")
    if not summary["flow_agent_reachability"]:
        lines.append("- none")

    lines += ["", "## OWASP Agentic Top 10", ""]
    for category in summary["owasp_agentic"]["categories"]:
        lines.append(
            f"- {category['id']} {category['title']}: "
            f"runtime={category['runtime_finding_count']} / "
            f"total={category['finding_count']}; "
            f"runtime repos={category['runtime_affected_repository_count']} / "
            f"affected repos={category['affected_repository_count']}"
        )
    lines += ["", "## Finding source contexts", ""]
    for key, value in sorted(summary["finding_source_contexts"].items()):
        lines.append(f"- {key}: {value}")
    lines += ["", "## Approval mechanisms", ""]
    for key, value in sorted(summary["approval_mechanisms"].items()):
        lines.append(f"- {key}: {value}")
    if not summary["approval_mechanisms"]:
        lines.append("- none")
    lines += ["", "## Mutation semantics", ""]
    for key, value in sorted(summary["mutation_semantics"].items()):
        lines.append(f"- {key}: {value}")
    lines += ["", "## Network semantics", ""]
    for key, value in sorted(summary["network_semantics"].items()):
        lines.append(f"- {key}: {value}")
    lines += ["", "## Most frequent findings", ""]
    for key, value in sorted(summary["rules"].items(), key=lambda kv: (-kv[1], kv[0]))[:30]:
        lines.append(f"- {key}: {value}")
    lines += ["", "## Coverage diagnostics", ""]
    for key, value in sorted(summary["diagnostics"].items(), key=lambda kv: (-kv[1], kv[0]))[:30]:
        lines.append(f"- {key}: {value}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-target")
    parser.add_argument("--manifest")
    parser.add_argument("--cohort")
    parser.add_argument("--output-prefix")
    args = parser.parse_args()

    if args.scan_target:
        try:
            print(json.dumps(scan_target(Path(args.scan_target)), separators=(",", ":")))
            return 0
        except Exception as exc:  # research runner must surface scanner failures per repository
            print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
            return 1

    if not args.manifest or not args.cohort or not args.output_prefix:
        parser.error("--manifest, --cohort and --output-prefix are required")

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    results: list[dict] = []
    with tempfile.TemporaryDirectory(prefix=f"horustrace-cohort-{args.cohort}-") as temp:
        root = Path(temp)
        for index, entry in enumerate(manifest["repositories"], start=1):
            print(f"[{index:02d}/{len(manifest['repositories'])}] {entry['repo']} @ {entry['sha'][:12]}", flush=True)
            item = scan_repo(root, entry)
            results.append(item)
            print(
                f"  clone={item.get('clone')} scan={item.get('scan')} "
                f"agents={item.get('agents', '-')} flows={item.get('flow_paths', '-')} "
                f"agent={item.get('proven_agent_reachable_flows', '-')} "
                f"nonagent={item.get('proven_non_agent_flows', '-')} "
                f"unknown={item.get('unknown_agent_reachability_flows', '-')} "
                f"findings={item.get('findings', '-')}",
                flush=True,
            )

    report = {
        "schema_version": 3,
        "cohort": args.cohort.lower(),
        "corpus": manifest["corpus"],
        "manifest_frozen_at": manifest["frozen_at"],
        "scanner_commit": os.environ.get(
            "HORUSTRACE_SCANNER_REF",
            os.environ.get("GITHUB_SHA", "local"),
        ),
        "summary": build_summary(results),
        "results": results,
    }
    json_path = Path(args.output_prefix + ".json")
    md_path = Path(args.output_prefix + ".md")
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    print(render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
