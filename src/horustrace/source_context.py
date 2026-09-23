from __future__ import annotations

from pathlib import Path

SOURCE_CONTEXTS = (
    "runtime",
    "test",
    "example",
    "tutorial",
    "notebook",
    "template-generated",
    "unknown",
)

NON_RUNTIME_SOURCE_CONTEXTS = frozenset(
    {
        "test",
        "example",
        "tutorial",
        "notebook",
        "template-generated",
    }
)

_TEST_DIRS = {"test", "tests", "testing"}
_EXAMPLE_DIRS = {"example", "examples", "sample", "samples", "demo", "demos"}
_TUTORIAL_DIRS = {
    "tutorial",
    "tutorials",
    "training",
    "lab",
    "labs",
    "workshop",
    "workshops",
    "course",
    "courses",
}
_TEMPLATE_DIRS = {
    "template",
    "templates",
    "generated",
    "fixtures",
    "benchmark",
    "benchmarks",
}


def path_parts_match(parts: set[str], markers: set[str]) -> bool:
    return any(
        part == marker
        or part.startswith((f"{marker}_", f"{marker}-"))
        or part.endswith((f"_{marker}", f"-{marker}"))
        for part in parts
        for marker in markers
    )


def classify_source_context(path: Path | None) -> str:
    """Classify a source path without reading or executing the target."""
    if path is None:
        return "unknown"
    lowered_parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    if path.suffix.lower() == ".ipynb":
        return "notebook"
    if path_parts_match(lowered_parts, _TEST_DIRS) or name.startswith(
        ("test_", "tests_")
    ):
        return "test"
    if path_parts_match(lowered_parts, _EXAMPLE_DIRS):
        return "example"
    if path_parts_match(lowered_parts, _TUTORIAL_DIRS):
        return "tutorial"
    if (
        path_parts_match(lowered_parts, _TEMPLATE_DIRS)
        or ".template." in name
        or name.endswith((".template", ".j2", ".jinja", ".jinja2"))
    ):
        return "template-generated"
    return "runtime"


def is_non_runtime_source_context(value: str | None) -> bool:
    return (value or "unknown") in NON_RUNTIME_SOURCE_CONTEXTS
