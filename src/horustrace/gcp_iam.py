"""Conservative GCP IAM enrichment from Cloud Asset Inventory exports."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from horustrace.models import EvidenceFact, Graph, Identity, SourceLocation

MAX_GCP_IAM_EXPORT_BYTES = 128 * 1024 * 1024
MAX_GCP_IAM_EXPORT_RECORDS = 100_000
MAX_GCP_IAM_EXPORT_LINE_BYTES = 5 * 1024 * 1024
_SERVICE_ACCOUNT_PREFIX = "serviceaccount:"
_SERVICE_ACCOUNT_SUFFIX = ".iam.gserviceaccount.com"


class GcpIamExportError(ValueError):
    """A supplied Cloud Asset Inventory IAM export is invalid or unsafe."""


@dataclass(frozen=True, slots=True)
class GcpIamBindingEvidence:
    principal: str
    role: str
    resource: str
    asset_type: str | None
    ancestors: tuple[str, ...]
    condition: dict[str, str] | None
    line: int

    @property
    def conditional(self) -> bool:
        return self.condition is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "role": self.role,
            "resource": self.resource,
            "asset_type": self.asset_type,
            "ancestors": list(self.ancestors),
            "condition": self.condition,
            "conditional": self.conditional,
            "line": self.line,
        }


@dataclass(frozen=True, slots=True)
class GcpIamEnrichmentSummary:
    records: int
    service_account_bindings: int
    matched_identities: int
    matched_bindings: int
    conditional_matched_bindings: int

    def as_dict(self) -> dict[str, int]:
        return {
            "records": self.records,
            "service_account_bindings": self.service_account_bindings,
            "matched_identities": self.matched_identities,
            "matched_bindings": self.matched_bindings,
            "conditional_matched_bindings": self.conditional_matched_bindings,
        }


def _canonical_service_account_principal(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    lowered = candidate.lower()
    if lowered.startswith(_SERVICE_ACCOUNT_PREFIX):
        email = candidate.split(":", 1)[1].strip().lower()
        if email.endswith(_SERVICE_ACCOUNT_SUFFIX) and "@" in email:
            return f"serviceAccount:{email}"
        return None
    if lowered.endswith(_SERVICE_ACCOUNT_SUFFIX) and "@" in candidate:
        return f"serviceAccount:{candidate.lower()}"
    return None


def _condition(raw: object) -> dict[str, str] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise GcpIamExportError("IAM binding condition must be an object")
    result: dict[str, str] = {}
    for key in ("title", "description", "expression", "location"):
        value = raw.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise GcpIamExportError(f"IAM binding condition.{key} must be a string")
        result[key] = value
    if not result:
        raise GcpIamExportError("IAM binding condition must contain supported string fields")
    return result


def _strings(raw: object, *, field: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise GcpIamExportError(f"{field} must be a list of strings")
    return list(raw)


def load_gcp_iam_export(
    path: Path,
) -> tuple[list[GcpIamBindingEvidence], int]:
    """Load service-account bindings from a CAI IAM_POLICY GCS NDJSON export."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise GcpIamExportError(f"cannot read GCP IAM export: {path}") from exc
    if not path.is_file():
        raise GcpIamExportError(f"GCP IAM export is not a file: {path}")
    if size > MAX_GCP_IAM_EXPORT_BYTES:
        raise GcpIamExportError("GCP IAM export exceeds the 128 MiB safety limit")

    evidence: list[GcpIamBindingEvidence] = []
    records = 0
    try:
        with path.open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                records += 1
                if records > MAX_GCP_IAM_EXPORT_RECORDS:
                    raise GcpIamExportError(
                        "GCP IAM export exceeds the 100000-record safety limit"
                    )
                if len(line.encode("utf-8")) > MAX_GCP_IAM_EXPORT_LINE_BYTES:
                    raise GcpIamExportError(
                        f"GCP IAM export line {line_number} exceeds the 5 MiB safety limit"
                    )
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise GcpIamExportError(
                        f"GCP IAM export line {line_number} is not valid JSON"
                    ) from exc
                if not isinstance(raw, dict):
                    raise GcpIamExportError(
                        f"GCP IAM export line {line_number} must be a JSON object"
                    )

                resource = raw.get("name")
                if not isinstance(resource, str) or not resource.strip():
                    raise GcpIamExportError(
                        f"GCP IAM export line {line_number} is missing asset name"
                    )
                asset_type = raw.get("assetType")
                if asset_type is not None and not isinstance(asset_type, str):
                    raise GcpIamExportError(
                        f"GCP IAM export line {line_number} assetType must be a string"
                    )
                ancestors = tuple(
                    _strings(raw.get("ancestors"), field="asset.ancestors")
                )
                policy = raw.get("iamPolicy")
                if policy is None:
                    continue
                if not isinstance(policy, dict):
                    raise GcpIamExportError(
                        f"GCP IAM export line {line_number} iamPolicy must be an object"
                    )
                bindings = policy.get("bindings") or []
                if not isinstance(bindings, list):
                    raise GcpIamExportError(
                        f"GCP IAM export line {line_number} iamPolicy.bindings must be a list"
                    )
                for binding in bindings:
                    if not isinstance(binding, dict):
                        raise GcpIamExportError(
                            f"GCP IAM export line {line_number} binding must be an object"
                        )
                    role = binding.get("role")
                    if not isinstance(role, str) or not role.strip():
                        raise GcpIamExportError(
                            f"GCP IAM export line {line_number} binding role must be a string"
                        )
                    members = _strings(
                        binding.get("members"),
                        field="iamPolicy.bindings.members",
                    )
                    condition = _condition(binding.get("condition"))
                    for member in members:
                        principal = _canonical_service_account_principal(member)
                        if principal is None:
                            continue
                        evidence.append(
                            GcpIamBindingEvidence(
                                principal=principal,
                                role=role.strip(),
                                resource=resource.strip(),
                                asset_type=asset_type.strip() if asset_type else None,
                                ancestors=ancestors,
                                condition=condition,
                                line=line_number,
                            )
                        )
    except UnicodeDecodeError as exc:
        raise GcpIamExportError("GCP IAM export is not valid UTF-8") from exc
    except OSError as exc:
        raise GcpIamExportError(f"cannot read GCP IAM export: {path}") from exc
    return evidence, records


def _identity_principals(identity: Identity) -> set[str]:
    values = [identity.name]
    for key in ("service_account", "principal"):
        value = identity.metadata.get(key)
        if isinstance(value, str):
            values.append(value)
    return {
        principal
        for value in values
        if (principal := _canonical_service_account_principal(value)) is not None
    }


def _dedupe_bindings(
    bindings: list[GcpIamBindingEvidence],
) -> list[GcpIamBindingEvidence]:
    seen: set[tuple[object, ...]] = set()
    result: list[GcpIamBindingEvidence] = []
    for binding in bindings:
        key = (
            binding.principal,
            binding.role,
            binding.resource,
            binding.asset_type,
            binding.ancestors,
            tuple(sorted((binding.condition or {}).items())),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(binding)
    return result


def enrich_graph_with_gcp_iam_export(
    graph: Graph,
    path: Path,
) -> GcpIamEnrichmentSummary:
    """Merge exact direct GCP IAM bindings into already-normalized GCP identities."""
    bindings, records = load_gcp_iam_export(path)
    by_principal: dict[str, list[GcpIamBindingEvidence]] = {}
    for binding in bindings:
        by_principal.setdefault(binding.principal, []).append(binding)

    matched_identity_keys: set[tuple[str, str]] = set()
    matched_bindings: set[tuple[object, ...]] = set()
    conditional_matched_bindings: set[tuple[object, ...]] = set()

    identities: list[Identity] = []
    seen_identity_ids: set[int] = set()
    for identity in graph.all_identities():
        if id(identity) in seen_identity_ids:
            continue
        seen_identity_ids.add(id(identity))
        identities.append(identity)

    for identity in identities:
        if identity.provider.lower() != "gcp":
            continue
        principals = _identity_principals(identity)
        matches = _dedupe_bindings(
            [
                binding
                for principal in principals
                for binding in by_principal.get(principal, [])
            ]
        )
        if not matches:
            continue

        matched_identity_keys.add((identity.name, identity.provider))
        unconditional_resources: set[str] = set()
        authority = list(identity.metadata.get("gcp_iam_bindings") or [])
        existing_authority = {
            json.dumps(item, sort_keys=True)
            for item in authority
            if isinstance(item, dict)
        }

        for binding in matches:
            binding_dict = binding.as_dict()
            serialized = json.dumps(binding_dict, sort_keys=True)
            if serialized not in existing_authority:
                authority.append(binding_dict)
                existing_authority.add(serialized)

            binding_key = (
                binding.principal,
                binding.role,
                binding.resource,
                binding.asset_type,
                binding.ancestors,
                tuple(sorted((binding.condition or {}).items())),
            )
            matched_bindings.add(binding_key)
            if binding.conditional:
                conditional_matched_bindings.add(binding_key)

            location = SourceLocation(path=path, line=binding.line)
            if binding.conditional:
                fact = f"gcp_iam_conditional_role={binding.role}@{binding.resource}"
            else:
                identity.roles.add(binding.role)
                unconditional_resources.add(binding.resource)
                fact = f"gcp_iam_role={binding.role}@{binding.resource}"
            evidence = EvidenceFact(
                subject=identity.name,
                fact=fact,
                origin="observed",
                location=location,
            )
            if evidence not in identity.provenance:
                identity.provenance.append(evidence)

        identity.metadata["gcp_iam_bindings"] = authority
        identity.metadata["gcp_iam_evidence_source"] = "cloud_asset_inventory_export"
        identity.metadata["gcp_iam_export_path"] = path.as_posix()
        if identity.resource_scope is None and len(unconditional_resources) == 1:
            identity.resource_scope = next(iter(unconditional_resources))

    return GcpIamEnrichmentSummary(
        records=records,
        service_account_bindings=len(bindings),
        matched_identities=len(matched_identity_keys),
        matched_bindings=len(matched_bindings),
        conditional_matched_bindings=len(conditional_matched_bindings),
    )
