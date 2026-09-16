"""Conservative diagnostics for unresolved Python agent configuration."""
import ast
from pathlib import Path

from agentreachguard.models import Graph, ScanDiagnostic, SourceLocation


def diagnose_python(path: Path, graph: Graph) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    sequences = {}
    assignments = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and node.value is not None:
                    assignments[target.id] = node.value
                    if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                        sequences[target.id] = node.value.elts
    agents = {a.location.line: a for a in graph.agents if a.location and a.location.path == path}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno not in agents:
            continue
        agent = agents[node.lineno]
        for keyword in node.keywords:
            if keyword.arg not in {"tools", "mcp_servers", "sub_agents"}:
                if keyword.arg is None:
                    graph.coverage.diagnostics.append(ScanDiagnostic(
                        "dynamic_configuration", "Expanded agent keyword arguments are not resolved.",
                        SourceLocation(path, node.lineno),
                    ))
                continue
            value = keyword.value
            elements = None
            if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                elements = value.elts
            elif isinstance(value, ast.Name):
                elements = sequences.get(value.id)
            if elements is None:
                graph.coverage.diagnostics.append(ScanDiagnostic(
                    "dynamic_configuration", "Agent configuration sequence could not be resolved.",
                    SourceLocation(path, value.lineno),
                ))
                continue
            if keyword.arg == "sub_agents":
                continue  # Resolved edges are checked during graph linking.
            resolved = {t.name for t in agent.tools} | {s.name for s in agent.mcp_servers}
            builtins = {str(t.metadata.get("adk_builtin")) for t in agent.tools}
            for element in elements:
                name = None
                if isinstance(element, ast.Name):
                    name = element.id
                elif isinstance(element, ast.Call):
                    func = element.func
                    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
                elif isinstance(element, ast.Attribute):
                    name = element.attr
                recognized = name in resolved | builtins
                assigned = assignments.get(name)
                if assigned is not None:
                    recognized = recognized or any(
                        item.location and item.location.line == assigned.lineno
                        for item in [*agent.tools, *agent.mcp_servers]
                    )
                if isinstance(element, ast.Call):
                    recognized = recognized or any(
                        t.location and t.location.line == element.lineno for t in agent.tools
                    ) or any(s.location and s.location.line == element.lineno for s in agent.mcp_servers)
                if not recognized:
                    graph.coverage.diagnostics.append(ScanDiagnostic(
                        "unresolved_tool", "A configured tool or MCP server could not be resolved.",
                        SourceLocation(path, element.lineno),
                    ))
