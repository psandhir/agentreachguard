#!/usr/bin/env python3
from __future__ import annotations
import json
import sys
from collections import Counter
from pathlib import Path
from horustrace.scanner import scan

root=Path(sys.argv[1]).resolve()
graph, findings=scan(root)

flows=[f.as_dict() for f in graph.flow_paths]
agents=[]
for agent in graph.agents:
    agents.append({
        "name":agent.name,
        "framework":agent.metadata.get("framework"),
        "location":str(agent.location.path.relative_to(root)) if agent.location and agent.location.path.is_relative_to(root) else (str(agent.location.path) if agent.location else None),
        "metadata":agent.metadata,
        "tools":[{
            "name":t.name,
            "kind":t.kind,
            "location":str(t.location.path.relative_to(root)) if t.location and t.location.path.is_relative_to(root) else (str(t.location.path) if t.location else None),
            "line":t.location.line if t.location else None,
            "capabilities":sorted(t.capabilities),
            "metadata":t.metadata,
        } for t in agent.tools],
    })

def rel_locations(flow):
    vals=[]
    for step in flow.get("steps",[]):
        loc=step.get("location")
        if loc and loc.get("path"):
            try: loc["path"]=str(Path(loc["path"]).resolve().relative_to(root))
            except ValueError: pass
    return flow

flows=[rel_locations(f) for f in flows]
summary={
  "scanner_target":"3528845d343f3764544699081eff37e4cff9dbfd",
  "repository":"evalstate/fast-agent",
  "repository_commit":"96ded66a3d21472047859808ae30095390607171",
  "agents":len(graph.agents),
  "tools":len(graph.all_tools()),
  "flows":len(flows),
  "mapped":sum(bool(f.get("agent")) for f in flows),
  "execution_contexts":dict(Counter(f.get("execution_context","unknown") for f in flows)),
  "agent_reachability":dict(Counter(f.get("agent_reachability","unknown") for f in flows)),
  "binding_basis":dict(Counter(((f.get("metadata") or {}).get("agent_binding") or {}).get("basis","none") for f in flows)),
  "reachability_basis":dict(Counter((f.get("metadata") or {}).get("agent_reachability_basis","none") for f in flows)),
  "coverage":graph.coverage.as_dict(),
  "findings":len(findings),
}
out={"summary":summary,"flows":flows,"agents":agents}
print(json.dumps(out,indent=2,default=str))
