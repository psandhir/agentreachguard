"""Conservative diagnostics for unresolved Python agent configuration."""

import ast
from pathlib import Path

from horustrace.limits import MAX_DIAGNOSTICS, ScanLimitError
from horustrace.models import Graph, ScanCoverage, ScanDiagnostic, SourceLocation


def add_diagnostic(coverage: ScanCoverage, diagnostic: ScanDiagnostic) -> None:
    """Append a bounded, de-duplicated coverage diagnostic."""
    key = (
        diagnostic.kind,
        diagnostic.location.path if diagnostic.location else None,
        diagnostic.location.line if diagnostic.location else None,
        diagnostic.message,
    )
    for existing in coverage.diagnostics:
        existing_key = (
            existing.kind,
            existing.location.path if existing.location else None,
            existing.location.line if existing.location else None,
            existing.message,
        )
        if existing_key == key:
            return
    if len(coverage.diagnostics) >= MAX_DIAGNOSTICS:
        raise ScanLimitError(f"coverage diagnostic limit exceeded ({MAX_DIAGNOSTICS})")
    coverage.diagnostics.append(diagnostic)


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
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not isinstance(node.func.value, ast.Name):
            continue
        sequence = sequences.get(node.func.value.id)
        if sequence is None:
            continue
        if node.func.attr == "append" and len(node.args) == 1:
            sequence.append(node.args[0])
        elif node.func.attr == "extend" and len(node.args) == 1:
            arg = node.args[0]
            if isinstance(arg, (ast.List, ast.Tuple, ast.Set)):
                sequence.extend(arg.elts)
            elif isinstance(arg, ast.Name) and arg.id in sequences:
                sequence.extend(sequences[arg.id])

    agents = {a.location.line: a for a in graph.agents if a.location and a.location.path == path}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno not in agents:
            continue
        agent = agents[node.lineno]
        for keyword in node.keywords:
            if keyword.arg not in {"tools", "mcp_servers", "sub_agents"}:
                if keyword.arg is None:
                    add_diagnostic(graph.coverage, ScanDiagnostic(
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
                add_diagnostic(graph.coverage, ScanDiagnostic(
                    "dynamic_configuration", "Agent configuration sequence could not be resolved.",
                    SourceLocation(path, value.lineno),
                ))
                continue
            if keyword.arg == "sub_agents":
                continue
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
                    add_diagnostic(graph.coverage, ScanDiagnostic(
                        "unresolved_tool", "A configured tool or MCP server could not be resolved.",
                        SourceLocation(path, element.lineno),
                    ))


def diagnose_dynamic_constructs(graph: Graph) -> None:
    """Record unsupported dynamic security configuration without claiming a safe default."""
    existing = {(diagnostic.kind, diagnostic.location.path if diagnostic.location else None,
                 diagnostic.location.line if diagnostic.location else None)
                for diagnostic in graph.coverage.diagnostics}
    for tool in graph.all_tools():
        if tool.metadata.get("dynamic_tool_filter"):
            diagnostic = ScanDiagnostic(
                "dynamic_tool_filter", "Tool filter exists but its allowed tool set could not be resolved.",
                tool.location,
            )
            key = (diagnostic.kind, tool.location.path if tool.location else None,
                   tool.location.line if tool.location else None)
            if key not in existing:
                add_diagnostic(graph.coverage, diagnostic)
                existing.add(key)
    for server in graph.all_mcp_servers():
        if server.url and server.authenticated is None:
            diagnostic = ScanDiagnostic(
                "authentication_unknown",
                "MCP authentication configuration could not be resolved statically.",
                server.location,
            )
            key = (
                diagnostic.kind,
                server.location.path if server.location else None,
                server.location.line if server.location else None,
            )
            if key not in existing:
                add_diagnostic(graph.coverage, diagnostic)
                existing.add(key)
        if server.metadata.get("dynamic_mcp_endpoint"):
            diagnostic = ScanDiagnostic(
                "dynamic_mcp_endpoint", "MCP endpoint or connection parameters could not be resolved.",
                server.location,
            )
            key = (diagnostic.kind, server.location.path if server.location else None,
                   server.location.line if server.location else None)
            if key not in existing:
                add_diagnostic(graph.coverage, diagnostic)
                existing.add(key)
    for agent in graph.agents:
        if agent.metadata.get("external_helper_semantics_unresolved"):
            diagnostic = ScanDiagnostic(
                "external_helper_semantics_unresolved",
                "An agent tool references an imported or arbitrary helper whose semantics could not be resolved.",
                agent.location,
            )
            key = (diagnostic.kind, agent.location.path if agent.location else None,
                   agent.location.line if agent.location else None)
            if key not in existing:
                add_diagnostic(graph.coverage, diagnostic)
                existing.add(key)
