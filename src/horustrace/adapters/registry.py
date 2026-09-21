"""Framework adapter registry for Python agent source files."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from horustrace.adapters.google_adk import is_google_adk_file
from horustrace.adapters.google_adk import scan_python_file as scan_google_adk_python
from horustrace.adapters.langgraph import is_langgraph_file
from horustrace.adapters.langgraph import scan_python_file as scan_langgraph_python
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
)


def detect_python_framework(path: Path) -> str | None:
    """Return the first supported framework detected for a Python source file."""
    for adapter in PYTHON_FRAMEWORK_ADAPTERS:
        if adapter.detector(path):
            return adapter.name
    return None


def scan_python_file(path: Path) -> Graph:
    """Normalize a supported Python agent framework without importing the target."""
    for adapter in PYTHON_FRAMEWORK_ADAPTERS:
        if adapter.detector(path):
            return adapter.scanner(path)
    return Graph()
