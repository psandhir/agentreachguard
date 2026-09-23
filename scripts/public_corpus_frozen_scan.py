#!/usr/bin/env python3
"""Scan a frozen public-repository corpus without executing target code.

The manifest pins every repository to an exact commit SHA. Repositories are fetched
at that SHA, statically preflighted for expected framework markers, and scanned with
the HorusTrace executable already installed in the workflow environment.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

CLONE_TIMEOUT = 180
SCAN_TIMEOUT = 240
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


def scanner_version(scanner: str) -> str:
    result = run([scanner, "--version"], timeout=30)
    text = (result.stdout or result.stderr).strip()
    return text or "unknown"


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
            return target, (result.stderr or result.stdout).strip()[-2000:]

    rev = run(["git", "-C", str(target), "rev-parse", "HEAD"], timeout=30)
    if rev.returncode != 0:
        return target, (rev.stderr or rev.stdout).strip()[-2000:]
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
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > PREFLIGHT_MAX_BYTES:
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
        "material": python_files > 0 and len(marker_files) > 0,
    }


def diagnostic_summary(diagnostics: list[dict]) -> tuple[dict[str, int], list[dict]]:
    counts = collections.Counter(
        str(item.get("kind") or item.get("code") or "unknown") for item in diagnostics
    )
    details: list[dict] = []
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


def finding_record(item: dict) -> dict:
    location = item.get("location") or {}
    return {
        "rule_id": item.get("rule_id"),
        "severity": item.get("severity"),
        "default_severity": item.get("default_severity"),
        "title": item.get("title"),
        "message": item.get("message"),
        "recommendation": item.get("recommendation"),
        "layer": item.get("layer"),
        "agent": item.get("agent"),
        "assessment": item.get("assessment"),
        "confidence": item.get("confidence"),
        "evidence": item.get("evidence") or [],
        "provenance": item.get("provenance") or [],
        "limitations": item.get("limitations") or [],
        "fingerprint": item.get("fingerprint"),
        "location": {
            "path": location.get("path"),
            "line": location.get("line"),
            "column": location.get("column"),
        } if location else None,
    }


def scan_repo(scanner: str, root: Path, entry: dict) -> dict:
    repo = entry["repo"]
    sha = entry["sha"]
    started = time.monotonic()
    result = {
        "tier": entry["tier"],
        "category": entry["category"],
        "repo": repo,
        "branch": entry["branch"],
        "commit": sha,
        "clone": "failed",
        "scan": "not_run",
    }

    try:
        target, error = fetch_frozen_repo(root, repo, sha)
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
        scan = run(
            [scanner, "scan", str(target), "--format", "json", "--fail-on", "none"],
            timeout=SCAN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        result["scan"] = "timeout"
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(target, ignore_errors=True)
        return result

    result["scan_returncode"] = scan.returncode
    if scan.returncode not in {0, 2}:
        result["scan"] = "error"
        result["scan_error"] = (scan.stderr or scan.stdout).strip()[-5000:]
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(target, ignore_errors=True)
        return result

    try:
        document = json.loads(scan.stdout)
    except json.JSONDecodeError:
        result["scan"] = "invalid_json"
        result["scan_error"] = scan.stdout.strip()[-5000:]
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        shutil.rmtree(target, ignore_errors=True)
        return result

    summary = document.get("summary", {})
    coverage = document.get("coverage", {})
    findings = document.get("findings", []) or []
    diagnostics = coverage.get("diagnostics", []) or []
    diagnostic_counts, diagnostic_details = diagnostic_summary(diagnostics)
    severity_counts = collections.Counter(
        str(item.get("severity") or "unknown") for item in findings
    )
    flow_resolution = (coverage.get("resolution") or {}).get("flows") or {}

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
            "agent_mapped_flows": int(flow_resolution.get("agent_mapped", 0) or 0),
            "attack_paths": int(summary.get("attack_paths", 0) or 0),
            "adg_nodes": int(summary.get("adg_nodes", 0) or 0),
            "adg_edges": int(summary.get("adg_edges", 0) or 0),
            "findings": len(findings),
            "severity_counts": dict(severity_counts),
            "rules": dict(
                collections.Counter(str(item.get("rule_id") or "unknown") for item in findings)
            ),
            "finding_details": [finding_record(item) for item in findings],
            "diagnostics": diagnostic_counts,
            "diagnostic_details": diagnostic_details,
        }
    )
    result["elapsed_seconds"] = round(time.monotonic() - started, 2)
    shutil.rmtree(target, ignore_errors=True)
    return result


def build_summary(results: list[dict]) -> dict:
    scanned = [item for item in results if item.get("scan") == "ok"]
    rule_counts: collections.Counter[str] = collections.Counter()
    severity_counts: collections.Counter[str] = collections.Counter()
    diagnostic_counts: collections.Counter[str] = collections.Counter()
    for item in scanned:
        rule_counts.update(item.get("rules", {}))
        severity_counts.update(item.get("severity_counts", {}))
        diagnostic_counts.update(item.get("diagnostics", {}))

    numeric = [
        "agents", "tools", "mcp_servers", "identities", "flow_paths",
        "agent_mapped_flows", "attack_paths", "adg_nodes", "adg_edges", "findings",
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
        "totals": {
            key: sum(int(item.get(key, 0) or 0) for item in scanned) for key in numeric
        },
        "severities": dict(severity_counts),
        "top_rules": rule_counts.most_common(30),
        "coverage_diagnostics": diagnostic_counts.most_common(30),
    }


def render_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# HorusTrace frozen public corpus — Cohort B baseline",
        "",
        f"- Scanner: {report['scanner_version']}",
        f"- Category: {report['selected_category']}",
        f"- Repositories requested: {s['requested']}",
        f"- Preflight material: {s['preflight_material']}/{s['requested']}",
        f"- Successfully cloned/scanned: {s['cloned']}/{s['scanned']}",
        f"- Coverage complete/incomplete: {s['complete']}/{s['incomplete']}",
        f"- Scanner errors/timeouts: {s['scan_errors']}/{s['scan_timeouts']}",
        "",
        "## Aggregate scanner output",
        "",
    ]
    for key, value in s["totals"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Severities", ""]
    if s["severities"]:
        for severity, count in sorted(s["severities"].items()):
            lines.append(f"- {severity}: {count}")
    else:
        lines.append("- none")

    lines += [
        "",
        "## Per repository",
        "",
        "| Repository | Preflight | Scan | Incomplete | Agents | Tools | MCP | Flows | Mapped | Paths | Findings | ADG nodes | Seconds |",
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in report["results"]:
        lines.append(
            "| {repo} | {material} | {scan} | {incomplete} | {agents} | {tools} | "
            "{mcp} | {flows} | {mapped} | {paths} | {findings} | {adg} | {seconds} |".format(
                repo=item["repo"],
                material="yes" if item.get("preflight", {}).get("material") else "no",
                scan=item.get("scan"),
                incomplete="yes" if item.get("coverage_incomplete") else "no",
                agents=item.get("agents", "-"),
                tools=item.get("tools", "-"),
                mcp=item.get("mcp_servers", "-"),
                flows=item.get("flow_paths", "-"),
                mapped=item.get("agent_mapped_flows", "-"),
                paths=item.get("attack_paths", "-"),
                findings=item.get("findings", "-"),
                adg=item.get("adg_nodes", "-"),
                seconds=item.get("elapsed_seconds", "-"),
            )
        )

    lines += ["", "## Most frequent findings", ""]
    for rule, count in s["top_rules"]:
        lines.append(f"- {rule}: {count}")
    if not s["top_rules"]:
        lines.append("- none")

    lines += ["", "## Coverage diagnostics", ""]
    for kind, count in s["coverage_diagnostics"]:
        lines.append(f"- {kind}: {count}")
    if not s["coverage_diagnostics"]:
        lines.append("- none")

    lines += ["", "## Preflight failures", ""]
    failures = [
        item for item in report["results"]
        if not item.get("preflight", {}).get("material", False)
    ]
    if failures:
        for item in failures:
            preflight = item.get("preflight", {})
            lines.append(
                f"- {item['repo']}: python_files={preflight.get('python_files', 0)}, "
                f"framework_marker_files={preflight.get('framework_marker_files', 0)}"
            )
    else:
        lines.append("- none")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--category", required=True)
    parser.add_argument("--output-prefix", required=True)
    args = parser.parse_args()

    scanner = shutil.which("horustrace")
    if scanner is None:
        raise SystemExit("horustrace executable not found")

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    selected = [
        item for item in manifest["repositories"] if item["category"] == args.category
    ]
    if not selected:
        raise SystemExit(f"No repositories selected for category {args.category}")

    version = scanner_version(scanner)
    results: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="horustrace-cohort-b-") as temp:
        root = Path(temp)
        for index, entry in enumerate(selected, start=1):
            print(
                f"[{index:02d}/{len(selected)}] {entry['repo']} @ {entry['sha'][:12]}",
                flush=True,
            )
            item = scan_repo(scanner, root, entry)
            results.append(item)
            print(
                f"  preflight={item.get('preflight', {}).get('material', '-')} "
                f"clone={item.get('clone')} scan={item.get('scan')} "
                f"agents={item.get('agents', '-')} findings={item.get('findings', '-')} "
                f"incomplete={item.get('coverage_incomplete', '-')}",
                flush=True,
            )

    report = {
        "schema_version": 1,
        "corpus": manifest["corpus"],
        "manifest_frozen_at": manifest["frozen_at"],
        "selected_category": args.category,
        "scanner_version": version,
        "summary": build_summary(results),
        "results": results,
    }
    json_path = Path(args.output_prefix + ".json")
    md_path = Path(args.output_prefix + ".md")
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    rendered = render_markdown(report)
    md_path.write_text(rendered, encoding="utf-8")
    print("\n--- COHORT B BASELINE REPORT ---\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
