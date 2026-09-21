#!/usr/bin/env python3
"""Run AgentReachGuard against a broad public GitHub agent corpus.

The target repositories are cloned with depth=1 and are never imported, installed,
or executed. AgentReachGuard scans them statically.
"""
from __future__ import annotations

import collections
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CORPUS = [
    # Google ADK
    ("google-adk", "google/adk-samples"),
    ("google-adk", "google/adk-python"),
    ("google-adk", "GoogleCloudPlatform/agent-starter-pack"),
    ("google-adk", "google-marketing-solutions/google_ads_adk"),
    ("google-adk", "box-community/google-adk-box-agent"),
    ("google-adk", "arjunprabhulal/google-adk-masterclass"),
    ("google-adk", "okahu-demos/adk-travel-agent"),
    ("google-adk", "Roji-val/A2A_ADK_MCP"),

    # OpenAI Agents SDK
    ("openai-agents", "openai/openai-agents-python"),
    ("openai-agents", "temporal-community/openai-agents-demos"),
    ("openai-agents", "lastmile-ai/openai-agents-mcp"),
    ("openai-agents", "slack-samples/bolt-python-starter-agent"),
    ("openai-agents", "Azure-Samples/python-ai-agent-frameworks-demos"),
    ("openai-agents", "pdeitel/Python-OpenAI-API-and-Intro-to-Agents-SDK"),
    ("openai-agents", "AsharibAli/agentic-ai-projects"),

    # LangGraph
    ("langgraph", "langchain-ai/langgraph-swarm-py"),
    ("langgraph", "langchain-ai/deepagents"),
    ("langgraph", "NirDiamant/GenAI_Agents"),
    ("langgraph", "NirDiamant/agents-towards-production"),
    ("langgraph", "gotohuman/examples-langgraph-py"),
    ("langgraph", "langchain-ai/agent-inbox-langgraph-example"),
    ("langgraph", "guy-hartstein/company-research-agent"),
    ("langgraph", "liangdabiao/langgraph_multi-agent-rag-customer-support"),

    # MCP / mixed agent projects
    ("mcp-mixed", "lastmile-ai/mcp-agent"),
    ("mcp-mixed", "evalstate/fast-agent"),
    ("mcp-mixed", "IBM/mcp-context-forge"),
    ("mcp-mixed", "ArcadeAI/arcade-mcp"),
    ("mcp-mixed", "juleswhite/python-agents-mcp-course"),
    ("mcp-mixed", "arjunprabhulal/adk-python-mcp-client"),
    ("mcp-mixed", "dabidstudio/python_mcp_agent"),
]

CLONE_TIMEOUT = 120
SCAN_TIMEOUT = 120


def run(command: list[str], *, timeout: int, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def one_repo(scanner: str, root: Path, category: str, repo: str) -> dict:
    slug = repo.replace("/", "__")
    target = root / slug
    result: dict = {
        "category": category,
        "repo": repo,
        "clone": "failed",
        "scan": "not_run",
    }

    started = time.monotonic()
    try:
        clone = run(
            [
                "git", "clone", "--depth", "1", "--filter=blob:none",
                f"https://github.com/{repo}.git", str(target),
            ],
            timeout=CLONE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        result["clone"] = "timeout"
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        return result

    if clone.returncode != 0:
        result["clone_error"] = clone.stderr.strip()[-1000:]
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        return result

    result["clone"] = "ok"
    rev = run(["git", "-C", str(target), "rev-parse", "HEAD"], timeout=15)
    if rev.returncode == 0:
        result["commit"] = rev.stdout.strip()

    try:
        scan = run([scanner, "scan", str(target), "--format", "json"], timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        result["scan"] = "timeout"
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(target, ignore_errors=True)
        return result

    result["scan_returncode"] = scan.returncode
    if scan.returncode not in {0, 2}:
        result["scan"] = "error"
        result["scan_error"] = (scan.stderr or scan.stdout).strip()[-2000:]
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(target, ignore_errors=True)
        return result

    try:
        document = json.loads(scan.stdout)
    except json.JSONDecodeError:
        result["scan"] = "invalid_json"
        result["scan_error"] = scan.stdout.strip()[-2000:]
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(target, ignore_errors=True)
        return result

    summary = document.get("summary", {})
    coverage = document.get("coverage", {})
    findings = document.get("findings", [])
    diagnostics = coverage.get("diagnostics", []) or []

    result.update(
        {
            "scan": "ok",
            "coverage_incomplete": bool(coverage.get("incomplete")),
            "agents": int(summary.get("agents", 0) or 0),
            "tools": int(summary.get("tools", 0) or 0),
            "mcp_servers": int(summary.get("mcp_servers", 0) or 0),
            "identities": int(summary.get("identities", 0) or 0),
            "flow_paths": int(summary.get("flow_paths", 0) or 0),
            "attack_paths": int(summary.get("attack_paths", 0) or 0),
            "adg_nodes": int(summary.get("adg_nodes", 0) or 0),
            "adg_edges": int(summary.get("adg_edges", 0) or 0),
            "findings": int(summary.get("findings", len(findings)) or 0),
            "rules": dict(collections.Counter(item.get("rule_id", "unknown") for item in findings)),
            "diagnostics": dict(
                collections.Counter(
                    str(item.get("kind") or item.get("code") or "unknown")
                    for item in diagnostics
                )
            ),
        }
    )
    result["elapsed_seconds"] = round(time.monotonic() - started, 2)
    shutil.rmtree(target, ignore_errors=True)
    return result


def build_summary(results: list[dict]) -> dict:
    scanned = [item for item in results if item["scan"] == "ok"]
    rule_counts: collections.Counter[str] = collections.Counter()
    diagnostic_counts: collections.Counter[str] = collections.Counter()
    for item in scanned:
        rule_counts.update(item.get("rules", {}))
        diagnostic_counts.update(item.get("diagnostics", {}))

    numeric = [
        "agents", "tools", "mcp_servers", "identities", "flow_paths",
        "attack_paths", "adg_nodes", "adg_edges", "findings",
    ]
    totals = {key: sum(int(item.get(key, 0)) for item in scanned) for key in numeric}
    return {
        "requested": len(results),
        "cloned": sum(item["clone"] == "ok" for item in results),
        "scanned": len(scanned),
        "complete": sum(not item.get("coverage_incomplete", False) for item in scanned),
        "incomplete": sum(item.get("coverage_incomplete", False) for item in scanned),
        "scan_errors": sum(item["scan"] == "error" for item in results),
        "scan_timeouts": sum(item["scan"] == "timeout" for item in results),
        "clone_failures": sum(item["clone"] == "failed" for item in results),
        "clone_timeouts": sum(item["clone"] == "timeout" for item in results),
        "totals": totals,
        "top_rules": rule_counts.most_common(20),
        "coverage_diagnostics": diagnostic_counts.most_common(20),
    }


def markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# AgentReachGuard public corpus validation",
        "",
        f"- Repositories requested: {s['requested']}",
        f"- Successfully cloned: {s['cloned']}",
        f"- Successfully scanned: {s['scanned']}",
        f"- Coverage complete: {s['complete']}",
        f"- Coverage incomplete: {s['incomplete']}",
        f"- Scanner errors: {s['scan_errors']}",
        f"- Scanner timeouts: {s['scan_timeouts']}",
        "",
        "## Aggregate scanner output",
        "",
    ]
    for key, value in s["totals"].items():
        lines.append(f"- {key}: {value}")

    lines += [
        "",
        "## Per repository",
        "",
        "| Category | Repository | Scan | Incomplete | Agents | Tools | MCP | Flows | Paths | Findings | ADG nodes | Seconds |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in report["results"]:
        lines.append(
            "| {category} | {repo} | {scan} | {incomplete} | {agents} | {tools} | "
            "{mcp} | {flows} | {paths} | {findings} | {adg} | {seconds} |".format(
                category=item["category"],
                repo=item["repo"],
                scan=item["scan"],
                incomplete="yes" if item.get("coverage_incomplete") else "no",
                agents=item.get("agents", "-"),
                tools=item.get("tools", "-"),
                mcp=item.get("mcp_servers", "-"),
                flows=item.get("flow_paths", "-"),
                paths=item.get("attack_paths", "-"),
                findings=item.get("findings", "-"),
                adg=item.get("adg_nodes", "-"),
                seconds=item.get("elapsed_seconds", "-"),
            )
        )

    lines += ["", "## Most frequent findings", ""]
    for rule, count in s["top_rules"]:
        lines.append(f"- {rule}: {count}")

    lines += ["", "## Coverage diagnostics", ""]
    if s["coverage_diagnostics"]:
        for kind, count in s["coverage_diagnostics"]:
            lines.append(f"- {kind}: {count}")
    else:
        lines.append("- none")

    failures = [
        item for item in report["results"]
        if item["clone"] != "ok" or item["scan"] not in {"ok"}
    ]
    lines += ["", "## Failures and timeouts", ""]
    if not failures:
        lines.append("- none")
    else:
        for item in failures:
            detail = item.get("scan_error") or item.get("clone_error") or ""
            detail = " ".join(detail.split())[:500]
            lines.append(f"- {item['repo']}: clone={item['clone']}, scan={item['scan']} {detail}")
    return "\n".join(lines) + "\n"


def main() -> int:
    scanner = shutil.which("agentreachguard")
    if scanner is None:
        raise SystemExit("agentreachguard executable not found")

    with tempfile.TemporaryDirectory(prefix="agentreachguard-public-corpus-") as temp:
        root = Path(temp)
        results = []
        for index, (category, repo) in enumerate(CORPUS, start=1):
            print(f"[{index:02d}/{len(CORPUS)}] scanning {repo}", flush=True)
            item = one_repo(scanner, root, category, repo)
            results.append(item)
            print(
                f"  clone={item['clone']} scan={item['scan']} "
                f"agents={item.get('agents', '-')} findings={item.get('findings', '-')} "
                f"incomplete={item.get('coverage_incomplete', '-')}",
                flush=True,
            )

    report = {
        "schema_version": 1,
        "corpus": "public-github-agent-repositories",
        "summary": build_summary(results),
        "results": results,
    }
    Path("public-corpus-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    text = markdown(report)
    Path("public-corpus-report.md").write_text(text, encoding="utf-8")

    print("\n--- PUBLIC CORPUS REPORT ---\n")
    print(text)
    print("PUBLIC_CORPUS_JSON=" + json.dumps(report, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
