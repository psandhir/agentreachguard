"""Versioned offline deployment/IAM evidence contract for deployed-authority analysis.

The loader is intentionally local-first: it reads an explicitly supplied JSON or YAML
snapshot, validates a small normalized schema, and never contacts a cloud API.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from horustrace.limits import MAX_FILE_SIZE_BYTES, validate_json_safety, validate_yaml_safety

DEPLOYMENT_EVIDENCE_SCHEMA_VERSION = 1


class DeploymentEvidenceError(ValueError):
    """Deployment evidence could not be loaded safely."""


def _mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DeploymentEvidenceError(f"{context} must be a mapping")
    return dict(value)


def _string(value: Any, context: str, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise DeploymentEvidenceError(f"{context} must be a non-empty string")
    return value.strip()


def _string_list(value: Any, context: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        raise DeploymentEvidenceError(f"{context} must be a string or list of strings")
    result: list[str] = []
    for index, item in enumerate(values):
        parsed = _string(item, f"{context}[{index}]")
        assert parsed is not None
        if parsed not in result:
            result.append(parsed)
    return tuple(sorted(result))


def _reject_unknown(document: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise DeploymentEvidenceError(
            f"{context} contains unsupported field(s): {', '.join(unknown)}"
        )


@dataclass(frozen=True, slots=True)
class DeploymentWorkloadEvidence:
    workload_id: str
    kind: str
    name: str
    identity: str
    agent: str | None = None
    project: str | None = None
    region: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "workload_id": self.workload_id,
            "kind": self.kind,
            "name": self.name,
            "identity": self.identity,
            "agent": self.agent,
            "project": self.project,
            "region": self.region,
            "metadata": dict(sorted(self.metadata.items())),
        }


@dataclass(frozen=True, slots=True)
class IAMBindingEvidence:
    principal: str
    role: str
    scope_kind: str
    scope_name: str
    permissions: tuple[str, ...] = ()
    inherited_from_kind: str | None = None
    inherited_from_name: str | None = None
    condition: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def inherited(self) -> bool:
        return bool(self.inherited_from_kind or self.inherited_from_name)

    def as_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "role": self.role,
            "scope": {"kind": self.scope_kind, "name": self.scope_name},
            "permissions": list(self.permissions),
            "inherited": self.inherited,
            "inherited_from": (
                {
                    "kind": self.inherited_from_kind,
                    "name": self.inherited_from_name,
                }
                if self.inherited
                else None
            ),
            "condition": self.condition,
            "metadata": dict(sorted(self.metadata.items())),
        }


@dataclass(frozen=True, slots=True)
class DeploymentEvidenceBundle:
    provider: str
    source: str
    workloads: tuple[DeploymentWorkloadEvidence, ...] = ()
    iam_bindings: tuple[IAMBindingEvidence, ...] = ()
    role_permissions: dict[str, tuple[str, ...]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = DEPLOYMENT_EVIDENCE_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "provider": self.provider,
            "source": self.source,
            "workloads": [
                item.as_dict()
                for item in sorted(self.workloads, key=lambda item: item.workload_id)
            ],
            "iam_bindings": [
                item.as_dict()
                for item in sorted(
                    self.iam_bindings,
                    key=lambda item: (
                        item.principal,
                        item.scope_kind,
                        item.scope_name,
                        item.role,
                    ),
                )
            ],
            "role_permissions": {
                role: list(permissions)
                for role, permissions in sorted(self.role_permissions.items())
            },
            "metadata": dict(sorted(self.metadata.items())),
        }


_ROOT_FIELDS = {
    "schema_version",
    "provider",
    "source",
    "workloads",
    "iam_bindings",
    "role_permissions",
    "metadata",
}
_WORKLOAD_FIELDS = {
    "workload_id",
    "kind",
    "name",
    "identity",
    "agent",
    "project",
    "region",
    "metadata",
}
_BINDING_FIELDS = {
    "principal",
    "role",
    "scope",
    "permissions",
    "inherited_from",
    "condition",
    "metadata",
}


def _parse_workload(value: Any, index: int) -> DeploymentWorkloadEvidence:
    document = _mapping(value, f"workloads[{index}]")
    _reject_unknown(document, _WORKLOAD_FIELDS, f"workloads[{index}]")
    metadata = document.get("metadata") or {}
    return DeploymentWorkloadEvidence(
        workload_id=_string(document.get("workload_id"), f"workloads[{index}].workload_id") or "",
        kind=_string(document.get("kind"), f"workloads[{index}].kind") or "",
        name=_string(document.get("name"), f"workloads[{index}].name") or "",
        identity=_string(document.get("identity"), f"workloads[{index}].identity") or "",
        agent=_string(document.get("agent"), f"workloads[{index}].agent", required=False),
        project=_string(document.get("project"), f"workloads[{index}].project", required=False),
        region=_string(document.get("region"), f"workloads[{index}].region", required=False),
        metadata=_mapping(metadata, f"workloads[{index}].metadata"),
    )


def _parse_scope(value: Any, context: str) -> tuple[str, str]:
    document = _mapping(value, context)
    _reject_unknown(document, {"kind", "name"}, context)
    kind = _string(document.get("kind"), f"{context}.kind")
    name = _string(document.get("name"), f"{context}.name")
    assert kind is not None and name is not None
    return kind, name


def _parse_inherited_from(value: Any, context: str) -> tuple[str | None, str | None]:
    if value is None:
        return None, None
    kind, name = _parse_scope(value, context)
    return kind, name


def _parse_binding(value: Any, index: int) -> IAMBindingEvidence:
    document = _mapping(value, f"iam_bindings[{index}]")
    _reject_unknown(document, _BINDING_FIELDS, f"iam_bindings[{index}]")
    scope_kind, scope_name = _parse_scope(
        document.get("scope"), f"iam_bindings[{index}].scope"
    )
    inherited_kind, inherited_name = _parse_inherited_from(
        document.get("inherited_from"), f"iam_bindings[{index}].inherited_from"
    )
    condition = document.get("condition")
    if condition is not None:
        condition = _mapping(condition, f"iam_bindings[{index}].condition")
    metadata = document.get("metadata") or {}
    return IAMBindingEvidence(
        principal=_string(document.get("principal"), f"iam_bindings[{index}].principal") or "",
        role=_string(document.get("role"), f"iam_bindings[{index}].role") or "",
        scope_kind=scope_kind,
        scope_name=scope_name,
        permissions=_string_list(
            document.get("permissions"), f"iam_bindings[{index}].permissions"
        ),
        inherited_from_kind=inherited_kind,
        inherited_from_name=inherited_name,
        condition=condition,
        metadata=_mapping(metadata, f"iam_bindings[{index}].metadata"),
    )


def _parse_role_permissions(value: Any) -> dict[str, tuple[str, ...]]:
    if value is None:
        return {}
    document = _mapping(value, "role_permissions")
    result: dict[str, tuple[str, ...]] = {}
    for role, permissions in document.items():
        parsed_role = _string(role, "role_permissions role")
        assert parsed_role is not None
        result[parsed_role] = _string_list(
            permissions, f"role_permissions.{parsed_role}"
        )
    return result


def load_deployment_evidence(path: Path) -> DeploymentEvidenceBundle:
    """Load and validate a normalized deployment evidence snapshot."""
    try:
        if not path.exists() or not path.is_file():
            raise DeploymentEvidenceError(f"{path}: deployment evidence must be a file")
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            raise DeploymentEvidenceError(f"{path}: deployment evidence exceeds the file safety limit")
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise DeploymentEvidenceError(f"{path}: deployment evidence is not valid UTF-8") from exc
    except OSError as exc:
        raise DeploymentEvidenceError(f"{path}: cannot read deployment evidence") from exc

    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            validate_json_safety(text)
            raw = json.loads(text)
        elif suffix in {".yaml", ".yml"}:
            validate_yaml_safety(text)
            raw = yaml.safe_load(text)
        else:
            raise DeploymentEvidenceError(
                f"{path}: deployment evidence must be JSON or YAML"
            )
    except (json.JSONDecodeError, yaml.YAMLError, ValueError) as exc:
        if isinstance(exc, DeploymentEvidenceError):
            raise
        raise DeploymentEvidenceError(f"{path}: invalid deployment evidence: {exc}") from exc

    document = _mapping(raw, "deployment evidence")
    _reject_unknown(document, _ROOT_FIELDS, "deployment evidence")
    schema_version = document.get("schema_version")
    if schema_version != DEPLOYMENT_EVIDENCE_SCHEMA_VERSION:
        raise DeploymentEvidenceError(
            f"deployment evidence schema_version must be "
            f"{DEPLOYMENT_EVIDENCE_SCHEMA_VERSION}"
        )
    provider = _string(document.get("provider"), "provider")
    assert provider is not None
    source = _string(document.get("source"), "source", required=False) or path.name

    workloads_raw = document.get("workloads")
    bindings_raw = document.get("iam_bindings")
    if workloads_raw is None:
        workloads_raw = []
    if bindings_raw is None:
        bindings_raw = []
    if not isinstance(workloads_raw, list):
        raise DeploymentEvidenceError("workloads must be a list")
    if not isinstance(bindings_raw, list):
        raise DeploymentEvidenceError("iam_bindings must be a list")
    metadata = _mapping(document.get("metadata") or {}, "metadata")

    return DeploymentEvidenceBundle(
        provider=provider.lower(),
        source=source,
        workloads=tuple(
            _parse_workload(item, index) for index, item in enumerate(workloads_raw)
        ),
        iam_bindings=tuple(
            _parse_binding(item, index) for index, item in enumerate(bindings_raw)
        ),
        role_permissions=_parse_role_permissions(document.get("role_permissions")),
        metadata=metadata,
        schema_version=schema_version,
    )
