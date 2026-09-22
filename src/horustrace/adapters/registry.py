"""Framework adapter registry for Python agent source files."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from horustrace.adapters.google_adk import is_google_adk_file
from horustrace.adapters.google_adk import scan_python_file as scan_google_adk_python
from horustrace.adapters.langgraph import is_langgraph_file
from horustrace.adapters.langgraph import scan_python_file as scan_langgraph_python
from horustrace.adapters.mcp_python import is_mcp_python_file
from horustrace.adapters.mcp_python import scan_python_file as scan_mcp_python
from horustrace.adapters.openai_agents import is_openai_agents_file
from horustrace.adapters.openai_agents import scan_python_file as scan_openai_python
from horustrace.models import Graph


@dataclass(frozen=True, slots=True)
class PythonFrameworkAdapter:
    name: str
    detector: Callable[[Path], bool]
    scanner: Callable[[Path], Graph]


PYTHON_FRAMEWORK_ADAPTERS: tuple[PythonFrameworkAdapter, ...] = (
    PythonFrameworkAdapter("google-adk", is_google_adk_file, scan_google_adk_python),
    PythonFrameworkAdapter("langgraph", is_langgraph_file, scan_langgraph_python),
    PythonFrameworkAdapter("openai-agents", is_openai_agents_file, scan_openai_python),
    PythonFrameworkAdapter("mcp-python", is_mcp_python_file, scan_mcp_python),
)


def detect_python_frameworks(path: Path) -> list[str]:
    """Return all supported frameworks detected for a Python source file."""
    return [adapter.name for adapter in PYTHON_FRAMEWORK_ADAPTERS if adapter.detector(path)]


def detect_python_framework(path: Path) -> str | None:
    """Return the first supported framework detected for compatibility callers."""
    frameworks = detect_python_frameworks(path)
    return frameworks[0] if frameworks else None


def _merge_graph(target: Graph, source: Graph) -> None:
    target.agents.extend(source.agents)
    target.unbound_tools.extend(source.unbound_tools)
    target.unbound_mcp_servers.extend(source.unbound_mcp_servers)
    target.identities.extend(source.identities)
    target.coverage.diagnostics.extend(source.coverage.diagnostics)


def scan_python_file(path: Path) -> Graph:
    """Normalize every supported framework present in a Python source file."""
    graph = Graph()
    for adapter in PYTHON_FRAMEWORK_ADAPTERS:
        if adapter.detector(path):
            _merge_graph(graph, adapter.scanner(path))
    return graph
