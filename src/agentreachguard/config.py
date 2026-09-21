"""Repository scanner configuration, separate from security intent manifests."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agentreachguard.models import Finding, Severity
from agentreachguard.rule_registry import RULE_REGISTRY

CONFIG_FILENAMES = (".horustrace.yaml", ".agentreachguard.yaml")


class ConfigError(ValueError):
    """Repository scanner configuration is invalid."""


class _UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ConfigError(f"duplicate configuration key '{key}' at line {key_node.start_mark.line + 1}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


@dataclass(frozen=True)
class RuleOverride:
    enabled: bool = True
    severity: Severity | None = None


@dataclass(frozen=True)
class ScanConfig:
    strict: bool = False
    rules: dict[str, RuleOverride] = field(default_factory=dict)
    source_path: Path | None = None


def load_config(root: Path, explicit: Path | None = None) -> ScanConfig:
    if explicit is not None:
        path = explicit
        if not path.exists():
            raise ConfigError(f"{path}: configuration file does not exist")
    else:
        defaults = [root / name for name in CONFIG_FILENAMES if (root / name).exists()]
        if len(defaults) > 1:
            raise ConfigError(f"{root}: multiple default scanner configuration files found")
        if not defaults:
            return ScanConfig()
        path = defaults[0]
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueLoader)
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"{path}: cannot read configuration") from exc
    if not isinstance(raw, dict) or set(raw) - {"version", "rules", "scanner"} or type(raw.get("version")) is not int or raw["version"] != 1:
        raise ConfigError(f"{path}: invalid configuration schema")
    scanner = raw.get("scanner", {})
    if not isinstance(scanner, dict) or set(scanner) - {"strict"} or type(scanner.get("strict", False)) is not bool:
        raise ConfigError(f"{path}: invalid scanner configuration")
    rules = raw.get("rules", {})
    if not isinstance(rules, dict):
        raise ConfigError(f"{path}: rules must be a mapping")
    parsed = {}
    for rule_id, item in rules.items():
        if rule_id not in RULE_REGISTRY or not isinstance(item, dict) or set(item) - {"enabled", "severity"}:
            raise ConfigError(f"{path}: invalid rule configuration for {rule_id}")
        if "enabled" in item and type(item["enabled"]) is not bool:
            raise ConfigError(f"{path}: enabled must be boolean for {rule_id}")
        try:
            severity = Severity.parse(item["severity"]) if "severity" in item else None
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{path}: invalid severity for {rule_id}") from exc
        parsed[rule_id] = RuleOverride(item.get("enabled", True), severity)
    return ScanConfig(scanner.get("strict", False), parsed, path)


def apply(config: ScanConfig, findings: list[Finding]) -> tuple[list[Finding], list[str]]:
    active, disabled = [], []
    for finding in findings:
        override = config.rules.get(finding.rule_id)
        if override and not override.enabled:
            disabled.append(finding.rule_id)
            continue
        if override and override.severity is not None:
            finding.severity = override.severity
        active.append(finding)
    return active, sorted(set(disabled))
