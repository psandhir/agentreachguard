"""Offline Google Cloud IAM snapshot enrichment."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from horustrace.models import EvidenceFact, Graph, Identity, SourceLocation

MAX_GCP_IAM_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_GCP_IAM_RESULTS = 50_000
MAX_GCP_IAM_GRANTS = 500_000


class GcpIamSnapshotError(ValueError):
    """A supplied GCP IAM snapshot is invalid or exceeds safety limits."""


@dataclass(frozen=True, slots=True)
class GcpIamGrant:
    principal: str
    role: str
    resource: str
    asset_type: str | None = None
    conditional: bool = False


@dataclass(frozen=True, slots=True)
class GcpIamSnapshot:
    grants: tuple[GcpIamGrant, ...]
    result_count: int

    @property
    def service_account_principals(self) -> set[str]:
        return {grant.principal for grant in self.grants}


def _canonical_service_account(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None

    lowered = candidate.lower()
    if lowered.startswith("serviceaccount:"):
        candidate = candidate.split(":", 1)[1].strip()
        lowered = candidate.lower()

    marker = "/serviceaccounts/"
    if marker in lowered:
        index = lowered.index(marker)
        candidate = candidate[index + len(marker):].strip()
        lowered = candidate.lower()

    if not lowered.endswith(".gserviceaccount.com") or "@" not in lowered:
        return None
    return lowered


def _records(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        records = raw
    elif isinstance(raw, dict) and isinstance(raw.get("results"), list):
        records = raw["results"]
    elif isinstance(raw, dict) and "resource" in raw and "policy" in raw:
        records = [raw]
    else:
        raise GcpIamSnapshotError(
            "GCP IAM snapshot must be a gcloud JSON list, REST results object, or single result"
        )

    if len(records) > MAX_GCP_IAM_RESULTS:
        raise GcpIamSnapshotError(
            f"GCP IAM snapshot exceeds the {MAX_GCP_IAM_RESULTS}-result safety limit"
        )
    if any(not isinstance(record, dict) for record in records):
        raise GcpIamSnapshotError("GCP IAM snapshot results must be JSON objects")
    return records


def load_gcp_iam_snapshot(path: Path) -> GcpIamSnapshot:
    """Parse Cloud Asset Inventory searchAllIamPolicies JSON output."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise GcpIamSnapshotError(f"{path}: cannot read GCP IAM snapshot") from exc
    if size > MAX_GCP_IAM_SNAPSHOT_BYTES:
        raise GcpIamSnapshotError(
            f"{path}: GCP IAM snapshot exceeds the 32 MiB safety limit"
        )

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GcpIamSnapshotError(f"{path}: GCP IAM snapshot is not valid JSON") from exc

    records = _records(raw)
    grants: set[GcpIamGrant] = set()

    for index, record in enumerate(records):
        resource = record.get("resource")
        if not isinstance(resource, str) or not resource.strip():
            raise GcpIamSnapshotError(
                f"{path}: result[{index}].resource must be a nonempty string"
            )
        asset_type = record.get("assetType")
        if asset_type is not None and not isinstance(asset_type, str):
            raise GcpIamSnapshotError(
                f"{path}: result[{index}].assetType must be a string"
            )

        policy = record.get("policy")
        if not isinstance(policy, dict):
            raise GcpIamSnapshotError(
                f"{path}: result[{index}].policy must be an object"
            )
        bindings = policy.get("bindings", [])
        if not isinstance(bindings, list):
            raise GcpIamSnapshotError(
                f"{path}: result[{index}].policy.bindings must be a list"
            )

        for binding_index, binding in enumerate(bindings):
            if not isinstance(binding, dict):
                raise GcpIamSnapshotError(
                    f"{path}: result[{index}].policy.bindings[{binding_index}] "
                    "must be an object"
                )
            role = binding.get("role")
            members = binding.get("members")
            if not isinstance(role, str) or not role.strip():
                raise GcpIamSnapshotError(
                    f"{path}: result[{index}].policy.bindings[{binding_index}].role "
                    "must be a nonempty string"
                )
            if not isinstance(members, list) or any(
                not isinstance(member, str) for member in members
            ):
                raise GcpIamSnapshotError(
                    f"{path}: result[{index}].policy.bindings[{binding_index}].members "
                    "must be a list of strings"
                )
            condition = binding.get("condition")
            if condition is not None and not isinstance(condition, dict):
                raise GcpIamSnapshotError(
                    f"{path}: result[{index}].policy.bindings[{binding_index}].condition "
                    "must be an object"
                )

            for member in members:
                principal = _canonical_service_account(member)
                if principal is None:
                    continue
                grants.add(
                    GcpIamGrant(
                        principal=principal,
                        role=role.strip(),
                        resource=resource.strip(),
                        asset_type=asset_type.strip() if asset_type else None,
                        conditional=condition is not None,
                    )
                )
                if len(grants) > MAX_GCP_IAM_GRANTS:
                    raise GcpIamSnapshotError(
                        f"{path}: GCP IAM snapshot exceeds the "
                        f"{MAX_GCP_IAM_GRANTS}-grant safety limit"
                    )

    return GcpIamSnapshot(
        grants=tuple(
            sorted(
                grants,
                key=lambda item: (
                    item.principal,
                    item.resource,
                    item.role,
                    item.asset_type or "",
                    item.conditional,
                ),
            )
        ),
        result_count=len(records),
    )


def _identity_principal(identity: Identity) -> str | None:
    if identity.provider not in {"gcp", "generic"}:
        return None
    return _canonical_service_account(identity.name)


def _grant_record(grant: GcpIamGrant) -> dict[str, Any]:
    return {
        "role": grant.role,
        "resource": grant.resource,
        "asset_type": grant.asset_type,
        "conditional": grant.conditional,
    }


def enrich_gcp_iam_snapshot(graph: Graph, path: Path) -> dict[str, Any]:
    """Enrich already-discovered GCP identities from an offline IAM search export."""
    snapshot = load_gcp_iam_snapshot(path)
    by_principal: dict[str, list[GcpIamGrant]] = {}
    for grant in snapshot.grants:
        by_principal.setdefault(grant.principal, []).append(grant)

    matched_principals: set[str] = set()
    seen_objects: set[int] = set()
    location = SourceLocation(path=path)

    for identity in graph.all_identities():
        if id(identity) in seen_objects:
            continue
        seen_objects.add(id(identity))
        principal = _identity_principal(identity)
        if principal is None:
            continue
        grants = by_principal.get(principal)
        if not grants:
            continue

        matched_principals.add(principal)
        if identity.provider == "generic":
            identity.provider = "gcp"

        existing_records = {
            (
                str(item.get("role")),
                str(item.get("resource")),
                str(item.get("asset_type")),
                bool(item.get("conditional")),
            )
            for item in identity.metadata.get("gcp_iam_grants", [])
            if isinstance(item, dict)
        }
        grant_records = list(identity.metadata.get("gcp_iam_grants", []))
        resources = set(identity.metadata.get("gcp_iam_resources", []))
        conditional_grants = 0

        for grant in grants:
            identity.roles.add(grant.role)
            resources.add(grant.resource)
            if grant.conditional:
                conditional_grants += 1
            key = (
                grant.role,
                grant.resource,
                str(grant.asset_type),
                grant.conditional,
            )
            if key not in existing_records:
                grant_records.append(_grant_record(grant))
                existing_records.add(key)
            fact = EvidenceFact(
                subject=identity.name,
                fact=(
                    f"gcp_iam_role={grant.role};resource={grant.resource};"
                    f"conditional={'true' if grant.conditional else 'false'}"
                ),
                origin="observed",
                location=location,
            )
            if fact not in identity.provenance:
                identity.provenance.append(fact)

        identity.metadata["gcp_iam_snapshot"] = path.name
        identity.metadata["gcp_iam_resources"] = sorted(resources)
        identity.metadata["gcp_iam_grants"] = sorted(
            grant_records,
            key=lambda item: (
                str(item.get("resource")),
                str(item.get("role")),
                bool(item.get("conditional")),
            ),
        )
        identity.metadata["gcp_iam_conditional_grants"] = conditional_grants

        if identity.resource_scope is None and len(resources) == 1:
            identity.resource_scope = next(iter(resources))

    unmatched = snapshot.service_account_principals - matched_principals
    return {
        "source": path.name,
        "results": snapshot.result_count,
        "service_account_principals": len(snapshot.service_account_principals),
        "grants": len(snapshot.grants),
        "matched_identities": len(matched_principals),
        "matched_grants": sum(
            len(by_principal[principal]) for principal in matched_principals
        ),
        "unmatched_service_account_principals": len(unmatched),
        "conditional_grants": sum(grant.conditional for grant in snapshot.grants),
        "permissions_expanded": False,
    }
