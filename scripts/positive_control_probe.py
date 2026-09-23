#!/usr/bin/env python3
import json, sys
from pathlib import Path
from horustrace.scanner import scan
from horustrace.analysis import build_attack_paths
from horustrace.adg import build_adg

root=Path(sys.argv[1]).resolve()
graph, findings=scan(root)
adg=build_adg(graph, root)
print(json.dumps({
  "agents":[{
    "name":a.name,
    "tools":[{
      "name":t.name,"approval":t.approval,"guardrails":t.guardrails,
      "capabilities":sorted(t.capabilities),"metadata":t.metadata
    } for t in a.tools]
  } for a in graph.agents],
  "flows":[f.as_dict() for f in graph.flow_paths],
  "attack_paths":[p.as_dict() for p in build_attack_paths(graph)],
  "approval_nodes":[n.as_dict() for n in adg.nodes if n.kind=="approval_control"],
  "guarded_edges":[e.as_dict() for e in adg.edges if e.kind=="GUARDED_BY"],
  "coverage":graph.coverage.as_dict(),
  "findings":[f.as_dict() for f in findings],
},indent=2,default=str))
