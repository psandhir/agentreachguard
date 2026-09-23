#!/usr/bin/env python3
"""Focused frozen FastAgent flow adjudication.

Clones only the pinned evalstate/fast-agent research target, never imports,
installs, or executes target code, and serializes HorusTrace FlowPath evidence.
"""
from __future__ import annotations

import collections
import json
import shutil
import tempfile
from pathlib import Path

from frozen_corpus_rescan import fetch_frozen_repo
from horustrace.config import load_config
from horustrace.scanner import scan

REPO = "evalstate/fast-agent"
SHA = "96ded66a3d21472047859808ae30095390607171"
OUTPUT = Path("fastagent-flow-adjudication.json")


def relative_path(value: str, root: Path) -> str:
    path = Path(value)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return path.as_posix()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="horustrace-fastagent-") as temp:
        root = Path(temp)
        target, error = fetch_frozen_repo(root, REPO, SHA)
        if error:
            raise RuntimeError(error)

        try:
            graph, findings = scan(target, config=load_config(target))
            flows = []
            for flow in graph.flow_paths:
                item = flow.as_dict()
                for step in item.get("steps", []):
                    location = step.get("location")
                    if location and location.get("path"):
                        location["path"] = relative_path(location["path"], target)
                flows.append(item)

            contexts = collections.Counter(f["execution_context"] for f in flows)
            reachability = collections.Counter(f["agent_reachability"] for f in flows)
            pairs = collections.Counter(
                f"{f['source_kind']}->{f['sink_kind']}" for f in flows
            )
            unknown = [
                flow for flow in flows
                if flow["agent_reachability"] == "unknown"
            ]

            report = {
                "repo": REPO,
                "commit": SHA,
                "coverage_incomplete": graph.coverage.incomplete,
                "agents": len(graph.agents),
                "tools": len(graph.all_tools()),
                "mcp_servers": len(graph.all_mcp_servers()),
                "findings": len(findings),
                "flow_count": len(flows),
                "flow_execution_contexts": dict(contexts),
                "flow_agent_reachability": dict(reachability),
                "flow_pairs": dict(pairs),
                "unknown_flow_count": len(unknown),
                "flows": flows,
            }
            OUTPUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

            print(f"repo={REPO} commit={SHA}")
            print(
                f"agents={report['agents']} tools={report['tools']} "
                f"mcp={report['mcp_servers']} findings={report['findings']}"
            )
            print(
                f"flows={report['flow_count']} contexts={dict(contexts)} "
                f"reachability={dict(reachability)}"
            )
            print(f"unknown_flows={len(unknown)}")
            for index, flow in enumerate(unknown, start=1):
                steps = " -> ".join(
                    f"{step['kind']}:{step['label']}@"
                    f"{(step.get('location') or {}).get('path')}:"
                    f"{(step.get('location') or {}).get('line')}"
                    for step in flow.get("steps", [])
                )
                print(
                    f"[{index:02d}] {flow['flow_id']} "
                    f"{flow['source_kind']}->{flow['sink_kind']} "
                    f"context={flow['execution_context']} agent={flow.get('agent')} "
                    f"basis={flow['basis']} confidence={flow['confidence']} "
                    f"steps={steps}"
                )
        finally:
            shutil.rmtree(target, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
