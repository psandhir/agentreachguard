#!/usr/bin/env python3
"""Run HorusTrace against a broad public GitHub agent corpus.

Targets are cloned with depth=1 and are never imported, installed, or executed.
Application repositories are reported separately from framework stress repositories
so SDK internals do not distort release-quality coverage metrics.
"""
from __future__ import annotations

import collections
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

CORPUS = [
    # tier, framework/category, repository
    ("application", "google-adk", "google/adk-samples"),
    ("framework-stress", "google-adk", "google/adk-python"),
    ("framework-stress", "google-adk", "GoogleCloudPlatform/agent-starter-pack"),
    ("application", "google-adk", "google-marketing-solutions/google_ads_adk"),
    ("application", "google-adk", "box-community/google-adk-box-agent"),
    ("application", "google-adk", "arjunprabhulal/google-adk-masterclass"),
    ("application", "google-adk", "okahu-demos/adk-travel-agent"),
    ("application", "google-adk", "Roji-val/A2A_ADK_MCP"),

    ("framework-stress", "openai-agents", "openai/openai-agents-python"),
    ("application", "openai-agents", "temporal-community/openai-agents-demos"),
    ("application", "openai-agents", "lastmile-ai/openai-agents-mcp"),
    ("application", "openai-agents", "slack-samples/bolt-python-starter-agent"),
    ("application", "openai-agents", "Azure-Samples/python-ai-agent-frameworks-demos"),
    ("application", "openai-agents", "pdeitel/Python-OpenAI-API-and-Intro-to-Agents-SDK"),
    ("application", "openai-agents", "AsharibAli/agentic-ai-projects"),

    ("framework-stress", "langgraph", "langchain-ai/langgraph-swarm-py"),
    ("framework-stress", "langgraph", "langchain-ai/deepagents"),
    ("application", "langgraph", "NirDiamant/GenAI_Agents"),
    ("application", "langgraph", "NirDiamant/agents-towards-production"),
    ("application", "langgraph", "gotohuman/examples-langgraph-py"),
    ("application", "langgraph", "langchain-ai/agent-inbox-langgraph-example"),
    ("application", "langgraph", "guy-hartstein/company-research-agent"),
    ("application", "langgraph", "liangdabiao/langgraph_multi-agent-rag-customer-support"),

    ("framework-stress", "mcp-mixed", "lastmile-ai/mcp-agent"),
    ("framework-stress", "mcp-mixed", "evalstate/fast-agent"),
    ("framework-stress", "mcp-mixed", "IBM/mcp-context-forge"),
    ("framework-stress", "mcp-mixed", "ArcadeAI/arcade-mcp"),
    ("application", "mcp-mixed", "juleswhite/python-agents-mcp-course"),
    ("application", "mcp-mixed", "arjunprabhulal/adk-python-mcp-client"),
    ("application", "mcp-mixed", "dabidstudio/python_mcp_agent"),
]

CLONE_TIMEOUT = 120
SCAN_TIMEOUT = 180


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


def _diagnostic_summary(diagnostics: list[dict]) -> tuple[dict[str, int], list[dict]]:
    counts = collections.Counter(
        str(item.get("kind") or item.get("code") or "unknown")
        for item in diagnostics
    )
    details = []
    for item in diagnostics:
        location = item.get("location") or {}
        details.append(
            {
                "diagnostic_id": item.get("diagnostic_id"),
                "kind": item.get("kind") or item.get("code"),
                "message": item.get("message"),
                "path": location.get("path"),
                "line": location.get("line"),
                "column": location.get("column"),
                "details": item.get("details") or {},
            }
        )
    return dict(counts), details


def one_repo(scanner: str, root: Path, tier: str, category: str, repo: str) -> dict:
    target = root / repo.replace("/", "__")
    result: dict = {
        "tier": tier,
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
        result["scan_error"] = (scan.stderr or scan.stdout).strip()[-3000:]
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(target, ignore_errors=True)
        return result

    try:
        document = json.loads(scan.stdout)
    except json.JSONDecodeError:
        result["scan"] = "invalid_json"
        result["scan_error"] = scan.stdout.strip()[-3000:]
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(target, ignore_errors=True)
        return result

    summary = document.get("summary", {})
    coverage = document.get("coverage", {})
    findings = document.get("findings", [])
    diagnostics = coverage.get("diagnostics", []) or []
    diagnostic_counts, diagnostic_details = _diagnostic_summary(diagnostics)

    result.update(
        {
            "scan": "ok",
            "coverage_incomplete": bool(coverage.get("incomplete")),
            "coverage_resolution": coverage.get("resolution", {}),
            "agents": int(summary.get("agents", 0) or 0),
            "tools": int(summary.get("tools", 0) or 0),
            "mcp_servers": int(summary.get("mcp_servers", 0) or 0),
            "identities": int(summary.get("identities", 0) or 0),
            "flow_paths": int(summary.get("flow_paths", 0) or 0),
            "attack_paths": int(summary.get("attack_paths", 0) or 0),
            "adg_nodes": int(summary.get("adg_nodes", 0) or 0),
            "adg_edges": int(summary.get("adg_edges", 0) or 0),
            "findings": int(summary.get("findings", len(findings)) or 0),
            "rules": dict(
                collections.Counter(item.get("rule_id", "unknown") for item in findings)
            ),
            "diagnostics": diagnostic_counts,
            "diagnostic_details": diagnostic_details,
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

    def tier_summary(tier: str) -> dict:
        selected = [item for item in scanned if item["tier"] == tier]
        return {
            "repositories": len(selected),
            "complete": sum(not item.get("coverage_incomplete", False) for item in selected),
            "incomplete": sum(item.get("coverage_incomplete", False) for item in selected),
            "totals": {
                key: sum(int(item.get(key, 0)) for item in selected)
                for key in numeric
            },
        }

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
        "application": tier_summary("application"),
        "framework_stress": tier_summary("framework-stress"),
        "totals": {
            key: sum(int(item.get(key, 0)) for item in scanned)
            for key in numeric
        },
        "top_rules": rule_counts.most_common(20),
        "coverage_diagnostics": diagnostic_counts.most_common(20),
    }


def markdown(report: dict) -> str:
    s = report["summary"]
    app = s["application"]
    stress = s["framework_stress"]
    lines = [
        "# HorusTrace public corpus validation",
        "",
        f"- Repositories requested: {s['requested']}",
        f"- Successfully cloned: {s['cloned']}",
        f"- Successfully scanned: {s['scanned']}",
        f"- Overall complete/incomplete: {s['complete']}/{s['incomplete']}",
        f"- Application corpus complete/incomplete: {app['complete']}/{app['incomplete']}",
        f"- Framework stress complete/incomplete: {stress['complete']}/{stress['incomplete']}",
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
        "| Tier | Category | Repository | Scan | Incomplete | Agents | Tools | MCP | Flows | Paths | Findings | ADG nodes | Seconds |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in report["results"]:
        lines.append(
            "| {tier} | {category} | {repo} | {scan} | {incomplete} | {agents} | "
            "{tools} | {mcp} | {flows} | {paths} | {findings} | {adg} | {seconds} |".format(
                tier=item["tier"],
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
    for kind, count in s["coverage_diagnostics"]:
        lines.append(f"- {kind}: {count}")
    if not s["coverage_diagnostics"]:
        lines.append("- none")

    lines += ["", "## Actionable diagnostic samples", ""]
    samples = 0
    for item in report["results"]:
        for diagnostic in item.get("diagnostic_details", []):
            location = diagnostic.get("path") or "n/a"
            line = diagnostic.get("line") or 1
            details = diagnostic.get("details") or {}
            framework = details.get("framework")
            suffix = f"; framework={framework}" if framework else ""
            lines.append(
                f"- {item['repo']}: {diagnostic.get('diagnostic_id')} "
                f"{diagnostic.get('kind')} at {location}:{line}: "
                f"{diagnostic.get('message')}{suffix}"
            )
            samples += 1
            if samples >= 100:
                break
        if samples >= 100:
            break
    if samples == 0:
        lines.append("- none")

    failures = [
        item for item in report["results"]
        if item["clone"] != "ok" or item["scan"] != "ok"
    ]
    lines += ["", "## Failures and timeouts", ""]
    if not failures:
        lines.append("- none")
    else:
        for item in failures:
            detail = item.get("scan_error") or item.get("clone_error") or ""
            detail = " ".join(detail.split())[:500]
            lines.append(
                f"- {item['repo']}: clone={item['clone']}, scan={item['scan']} {detail}"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    scanner = shutil.which("horustrace")
    if scanner is None:
        raise SystemExit("horustrace executable not found")

    requested_tier = os.environ.get("HORUSTRACE_CORPUS_TIER", "all").strip().lower()
    if requested_tier not in {"all", "application", "framework-stress"}:
        raise SystemExit(
            "HORUSTRACE_CORPUS_TIER must be all, application, or framework-stress"
        )
    selected = [
        item for item in CORPUS
        if requested_tier == "all" or item[0] == requested_tier
    ]

    with tempfile.TemporaryDirectory(prefix="horustrace-public-corpus-") as temp:
        root = Path(temp)
        results = []
        for index, (tier, category, repo) in enumerate(selected, start=1):
            print(f"[{index:02d}/{len(selected)}] scanning {repo}", flush=True)
            item = one_repo(scanner, root, tier, category, repo)
            results.append(item)
            print(
                f"  tier={tier} clone={item['clone']} scan={item['scan']} "
                f"agents={item.get('agents', '-')} mcp={item.get('mcp_servers', '-')} "
                f"findings={item.get('findings', '-')} "
                f"incomplete={item.get('coverage_incomplete', '-')}",
                flush=True,
            )

    report = {
        "schema_version": 2,
        "corpus": "public-github-agent-repositories",
        "selected_tier": requested_tier,
        "summary": build_summary(results),
        "results": results,
    }
    Path("public-corpus-report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    rendered = markdown(report)
    Path("public-corpus-report.md").write_text(rendered, encoding="utf-8")

    print("\n--- PUBLIC CORPUS REPORT ---\n")
    print(rendered)
    print("PUBLIC_CORPUS_JSON=" + json.dumps(report, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
