#!/usr/bin/env python3
"""Discover a real public positive-control agent data flow for Issue #25.

Each candidate is fetched at an exact public commit and statically scanned only.
Target repositories are never imported, installed, or executed.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path

from frozen_corpus_rescan import fetch_frozen_repo
from horustrace.config import load_config
from horustrace.scanner import scan

CANDIDATES = [
    ("ed-donner/action", "b7e5e52836f9e8c7b1698cdb666a26279861f995"),
    ("xiasong0501/seedance_prompt", "55f7a4d78bdabe166a70bb16bd032fed96424509"),
    ("DPrimasso/primo-code-assistant", "533ae183b94f60ee2b1f6f0e4cfcf4e926578a99"),
    ("waytlion/OpenAi-agent", "e0f224799b96573a643d4c963e10b3280a457225"),
    ("disler/claude-code-is-programmable", "388926529ccdf78b7090ee221157e85953f739aa"),
    ("meetstream-ai/meetstream-agent", "9d5aa7362a32d8a804c0d4c4249e31ed56e487cd"),
    ("GoogleCloudPlatform/devrel-demos", "68476ce6028020bac0fbbe60d9626de6a1c7e60f"),
    ("AureliusOctavion/agent-boundary-scan", "9cdf4ce5b3fd5e1d5d48be012fe51d5f3f3adbf0"),
]
OUTPUT = Path("issue25-positive-control-discovery.json")


def normalize_flow(flow, target: Path) -> dict:
    item = flow.as_dict()
    for step in item.get("steps", []):
        loc = step.get("location")
        if loc and loc.get("path"):
            try:
                loc["path"] = Path(loc["path"]).resolve().relative_to(target.resolve()).as_posix()
            except (ValueError, OSError):
                pass
    return item


def main() -> int:
    results = []
    with tempfile.TemporaryDirectory(prefix="horustrace-issue25-") as temp:
        root = Path(temp)
        for index, (repo, sha) in enumerate(CANDIDATES, start=1):
            print(f"[{index:02d}/{len(CANDIDATES)}] {repo} @ {sha[:12]}", flush=True)
            started = time.monotonic()
            target, error = fetch_frozen_repo(root, repo, sha)
            if error:
                results.append({"repo": repo, "commit": sha, "status": "clone_error", "error": error})
                print(f"  clone_error={error[-300:]}", flush=True)
                continue
            try:
                graph, findings = scan(target, config=load_config(target))
                flows = [normalize_flow(flow, target) for flow in graph.flow_paths]
                mapped = [flow for flow in flows if flow.get("agent")]
                proven = [
                    flow for flow in flows
                    if flow.get("agent_reachability") == "proven_agent_reachable"
                ]
                result = {
                    "repo": repo,
                    "commit": sha,
                    "status": "ok",
                    "coverage_incomplete": graph.coverage.incomplete,
                    "agents": len(graph.agents),
                    "tools": len(graph.all_tools()),
                    "flows": len(flows),
                    "mapped_flows": len(mapped),
                    "proven_agent_reachable_flows": len(proven),
                    "findings": len(findings),
                    "mapped_flow_details": mapped,
                    "elapsed_seconds": round(time.monotonic() - started, 2),
                }
                results.append(result)
                print(
                    f"  agents={result['agents']} tools={result['tools']} flows={result['flows']} "
                    f"mapped={result['mapped_flows']} proven={result['proven_agent_reachable_flows']} "
                    f"findings={result['findings']} incomplete={result['coverage_incomplete']}",
                    flush=True,
                )
                for flow in mapped:
                    print(
                        f"    MAPPED agent={flow.get('agent')} "
                        f"{flow.get('source_kind')}->{flow.get('sink_kind')} "
                        f"basis={(flow.get('metadata') or {}).get('agent_binding')}",
                        flush=True,
                    )
            except Exception as exc:
                results.append({
                    "repo": repo, "commit": sha, "status": "scan_error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "elapsed_seconds": round(time.monotonic() - started, 2),
                })
                print(f"  scan_error={type(exc).__name__}: {exc}", flush=True)
            finally:
                shutil.rmtree(target, ignore_errors=True)

    report = {
        "scanner_baseline": os.getenv("HORUSTRACE_SCANNER_REF", "3528845d343f3764544699081eff37e4cff9dbfd"),
        "candidate_count": len(CANDIDATES),
        "positive_controls": [
            result for result in results
            if result.get("mapped_flows", 0) > 0
        ],
        "results": results,
    }
    OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"positive_controls={len(report['positive_controls'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
