"""Hard safety ceilings for scanning untrusted repositories."""

from __future__ import annotations

from typing import Any

import yaml

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
MAX_FILES_VISITED = 10_000
MAX_YAML_BYTES = 2 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_YAML_ALIAS_COUNT = 50
MAX_YAML_NESTING = 50
MAX_DIAGNOSTICS = 1_000


class ScanLimitError(ValueError):
    """A scan safety ceiling prevented complete analysis."""


def validate_yaml_safety(text: str) -> None:
    """Reject alias-heavy or deeply nested YAML without constructing targets."""
    if len(text.encode("utf-8")) > MAX_YAML_BYTES:
        raise ScanLimitError("YAML input exceeds the configured size limit")
    events = list(yaml.parse(text, Loader=yaml.SafeLoader))
    aliases = sum(isinstance(event, yaml.events.AliasEvent) for event in events)
    if aliases > MAX_YAML_ALIAS_COUNT:
        raise ScanLimitError("YAML input exceeds the configured alias limit")
    depth = 0
    maximum_depth = 0
    for event in events:
        if isinstance(event, (yaml.events.SequenceStartEvent, yaml.events.MappingStartEvent)):
            depth += 1
            maximum_depth = max(maximum_depth, depth)
        elif isinstance(event, (yaml.events.SequenceEndEvent, yaml.events.MappingEndEvent)):
            depth -= 1
    if maximum_depth > MAX_YAML_NESTING:
        raise ScanLimitError("YAML input exceeds the configured nesting limit")


def validate_json_safety(text: str) -> None:
    if len(text.encode("utf-8")) > MAX_JSON_BYTES:
        raise ScanLimitError("JSON input exceeds the configured size limit")


def nesting_depth(value: Any, depth: int = 0) -> int:
    if isinstance(value, dict):
        return max([depth, *(nesting_depth(item, depth + 1) for item in value.values())])
    if isinstance(value, list):
        return max([depth, *(nesting_depth(item, depth + 1) for item in value)])
    return depth
