"""Trust Boundary Classification v1 for effective agent authority.

This module describes authority shape and supported before/after boundary crossings. It
does not assign a numeric risk score and does not claim runtime exploitability.
Unknown or incomparable evidence is preserved rather than forced into an escalation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from horustrace.effective_authority import EffectiveAuthorityRelationship
from horustrace.heuristics import (
    BROAD_OAUTH_SCOPES,
    permission_looks_wildcard,
    role_looks_admin,
)

TRUST_BOUNDARY_SCHEMA_VERSION = 1

MUTATION_CLASSES = (
    "no_mutation",
    "local_session_mutation",
    "internal_mutation_unspecified",
    "persistent_internal_mutation",
    "external_side_effect",
    "destructive_mutation",
    "security_identity_sensitive_mutation",
    "unknown",
)
NETWORK_CLASSES = (
    "no_external_network",
    "fixed_destination",
    "provider_constrained_destination",
    "internet_retrieval",
    "arbitrary_egress",
    "unknown",
)
IDENTITY_CLASSES = (
    "workload_service_identity",
    "oauth_delegated_authority",
    "iam_authority",
    "broad_privileged_authority",
    "unknown",
)
CONTROL_CLASSES = (
    "mandatory_approval",
    "guardrail_control",
    "explicitly_no_approval",
    "unknown",
)
MCP_SCOPE_CLASSES = (
    "explicit_allowlist",
    "denylist_only",
    "dynamic_scope",
    "unknown",
    "not_applicable",
)

# These orders express widening only for classes with a supported monotonic relation.
# They are not user-facing risk scores.
_MUTATION_ORDER = (
    "no_mutation",
    "local_session_mutation",
    "internal_mutation_unspecified",
    "persistent_internal_mutation",
    "external_side_effect",
    "destructive_mutation",
    "security_identity_sensitive_mutation",
)
_NETWORK_ORDER = (
    "no_external_network",
    "fixed_destination",
    "provider_constrained_destination",
    "internet_retrieval",
    "arbitrary_egress",
)
_IDENTITY_ORDER = (
    "workload_service_identity",
    "oauth_delegated_authority",
    "iam_authority",
    "broad_privileged_authority",
)
_CONTROL_STRENGTH = (
    "explicitly_no_approval",
    "guardrail_control",
    "mandatory_approval",
)
_MCP_SCOPE_ORDER = (
    "explicit_allowlist",
    "denylist_only",
)


@dataclass(frozen=True, slots=True)
class BoundaryDimension:
    classification: str
    evidence: tuple[str, ...] = ()
    resolution: str = "resolved"

    def as_dict(self) -> dict[str, Any]:
        return {
            "class": self.classification,
            "resolution": self.resolution,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class TrustBoundaryClassification:
    authority_relationship_id: str
    agent: str
    target_kind: str
    target_name: str
    mutation: BoundaryDimension
    network: BoundaryDimension
    identity: BoundaryDimension
    control: BoundaryDimension
    mcp_scope: BoundaryDimension

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TRUST_BOUNDARY_SCHEMA_VERSION,
            "authority_relationship_id": self.authority_relationship_id,
            "agent": self.agent,
            "target": {"kind": self.target_kind, "name": self.target_name},
            "dimensions": {
                "mutation": self.mutation.as_dict(),
                "network": self.network.as_dict(),
                "identity": self.identity.as_dict(),
                "control": self.control.as_dict(),
                "mcp_scope": self.mcp_scope.as_dict(),
            },
            "runtime_effectiveness": "not_verified",
        }


@dataclass(frozen=True, slots=True)
class TrustBoundaryCrossing:
    authority_relationship_id: str
    family: str
    before: str
    after: str
    direction: str

    @property
    def crossing_id(self) -> str:
        return (
            f"trust-boundary-v1:{self.authority_relationship_id}:"
            f"{self.family}:{self.before}->{self.after}"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "crossing_id": self.crossing_id,
            "authority_relationship_id": self.authority_relationship_id,
            "family": self.family,
            "before": self.before,
            "after": self.after,
            "direction": self.direction,
            "runtime_effectiveness": "not_verified",
        }


def _mutation_boundary(
    relationship: EffectiveAuthorityRelationship,
) -> BoundaryDimension:
    capabilities = set(relationship.capabilities)
    semantic = relationship.semantics.get("mutation")

    # Normalized identity-admin authority is stronger evidence than a name-derived
    # sensitive-write hint and supports a security/identity-sensitive classification.
    if "identity.admin" in capabilities:
        return BoundaryDimension(
            "security_identity_sensitive_mutation",
            ("capability=identity.admin",),
        )
    if semantic == "destructive_write" or "destructive.write" in capabilities:
        return BoundaryDimension(
            "destructive_mutation",
            ("mutation=destructive_write",),
        )
    if semantic == "external_side_effect" or "external.write" in capabilities:
        return BoundaryDimension(
            "external_side_effect",
            ("mutation=external_side_effect",),
        )
    if semantic == "persistent_internal_write":
        return BoundaryDimension(
            "persistent_internal_mutation",
            ("mutation=persistent_internal_write",),
        )
    if semantic == "local_session_state_write":
        return BoundaryDimension(
            "local_session_mutation",
            ("mutation=local_session_state_write",),
        )
    if semantic == "internal_write_unspecified" or "data.write" in capabilities:
        return BoundaryDimension(
            "internal_mutation_unspecified",
            ("capability=data.write",),
            "partial",
        )
    if (
        "process.execute" in capabilities
        or "computer.control" in capabilities
        or relationship.target_kind == "mcp_server"
    ):
        return BoundaryDimension(
            "unknown",
            ("mutation_effect_not_bounded_by_normalized_capability",),
            "unknown",
        )
    if relationship.dimensions.get("capabilities") == "unknown":
        return BoundaryDimension("unknown", (), "unknown")
    return BoundaryDimension("no_mutation", ("no_write_capability_observed",))


def _network_boundary(
    relationship: EffectiveAuthorityRelationship,
) -> BoundaryDimension:
    capabilities = set(relationship.capabilities)
    if "network.external" not in capabilities:
        return BoundaryDimension(
            "no_external_network",
            ("capability=network.external absent",),
        )

    semantic = relationship.semantics.get("network")
    if semantic == "arbitrary_egress":
        return BoundaryDimension("arbitrary_egress", ("network=arbitrary_egress",))
    if semantic == "arbitrary_internet_retrieval":
        return BoundaryDimension(
            "internet_retrieval",
            ("network=arbitrary_internet_retrieval",),
        )
    if semantic == "fixed_provider_network":
        return BoundaryDimension(
            "provider_constrained_destination",
            ("network=fixed_provider_network",),
        )

    destination_status = relationship.dimensions.get("destinations", "unknown")
    if destination_status == "resolved" and relationship.destinations:
        if all(item.get("restricted") is True for item in relationship.destinations):
            return BoundaryDimension(
                "fixed_destination",
                ("restricted_destination_evidence",),
            )
    return BoundaryDimension("unknown", (), "unknown")


def _identity_boundary(
    relationship: EffectiveAuthorityRelationship,
) -> BoundaryDimension:
    identity = relationship.identity
    if identity is None or relationship.dimensions.get("identity") == "unknown":
        return BoundaryDimension("unknown", (), "unknown")

    roles = set(identity.get("roles") or [])
    permissions = set(identity.get("permissions") or [])
    oauth_scopes = set(identity.get("oauth_scopes") or [])

    if (
        any(role_looks_admin(role) for role in roles)
        or any(permission_looks_wildcard(permission) for permission in permissions)
        or bool(oauth_scopes & BROAD_OAUTH_SCOPES)
    ):
        return BoundaryDimension(
            "broad_privileged_authority",
            ("broad_role_permission_or_oauth_scope",),
        )
    if roles or permissions:
        return BoundaryDimension(
            "iam_authority",
            ("iam_role_or_permission_evidence",),
        )
    if oauth_scopes:
        return BoundaryDimension(
            "oauth_delegated_authority",
            ("oauth_scope_evidence",),
        )
    return BoundaryDimension(
        "workload_service_identity",
        ("resolved_identity",),
    )


def _control_boundary(
    relationship: EffectiveAuthorityRelationship,
) -> BoundaryDimension:
    approval = relationship.approval or {}
    if approval.get("required") is True:
        return BoundaryDimension("mandatory_approval", ("approval=true",))
    if approval.get("guardrails") is True or approval.get("inherited_control") is True:
        return BoundaryDimension(
            "guardrail_control",
            ("guardrail_or_inherited_control",),
        )
    if approval.get("required") is False:
        return BoundaryDimension("explicitly_no_approval", ("approval=false",))
    return BoundaryDimension("unknown", (), "unknown")


def _mcp_scope_boundary(
    relationship: EffectiveAuthorityRelationship,
) -> BoundaryDimension:
    if relationship.target_kind != "mcp_server":
        return BoundaryDimension("not_applicable", (), "not_applicable")

    scope = relationship.tool_scope or {}
    scope_kind = str(scope.get("scope") or "unknown")
    if scope_kind == "explicit_allowlist":
        return BoundaryDimension("explicit_allowlist", ("tool_scope=explicit_allowlist",))
    if scope_kind == "denylist_only":
        return BoundaryDimension("denylist_only", ("tool_scope=denylist_only",), "partial")
    if scope_kind in {"dynamic_filter", "filtered"}:
        return BoundaryDimension("dynamic_scope", (f"tool_scope={scope_kind}",), "partial")
    return BoundaryDimension("unknown", (), "unknown")


def classify_relationship(
    relationship: EffectiveAuthorityRelationship,
) -> TrustBoundaryClassification:
    return TrustBoundaryClassification(
        authority_relationship_id=relationship.relationship_id,
        agent=relationship.agent,
        target_kind=relationship.target_kind,
        target_name=relationship.target_name,
        mutation=_mutation_boundary(relationship),
        network=_network_boundary(relationship),
        identity=_identity_boundary(relationship),
        control=_control_boundary(relationship),
        mcp_scope=_mcp_scope_boundary(relationship),
    )


def _ordered_direction(before: str, after: str, order: tuple[str, ...]) -> str | None:
    if before not in order or after not in order or before == after:
        return None
    return "expanded" if order.index(after) > order.index(before) else "narrowed"


def _control_direction(before: str, after: str) -> str | None:
    if before not in _CONTROL_STRENGTH or after not in _CONTROL_STRENGTH or before == after:
        return None
    return (
        "weakened"
        if _CONTROL_STRENGTH.index(after) < _CONTROL_STRENGTH.index(before)
        else "strengthened"
    )


def classify_boundary_crossings(
    before: EffectiveAuthorityRelationship,
    after: EffectiveAuthorityRelationship,
) -> list[TrustBoundaryCrossing]:
    if before.relationship_id != after.relationship_id:
        raise ValueError("trust-boundary comparison requires the same authority relationship")

    left = classify_relationship(before)
    right = classify_relationship(after)
    comparisons = (
        ("mutation", left.mutation, right.mutation, _MUTATION_ORDER, "authority"),
        ("network", left.network, right.network, _NETWORK_ORDER, "authority"),
        ("identity", left.identity, right.identity, _IDENTITY_ORDER, "authority"),
        ("mcp_scope", left.mcp_scope, right.mcp_scope, _MCP_SCOPE_ORDER, "authority"),
    )
    crossings: list[TrustBoundaryCrossing] = []

    for family, old, new, order, _ in comparisons:
        if old.resolution == "unknown" or new.resolution == "unknown":
            continue
        direction = _ordered_direction(old.classification, new.classification, order)
        if direction is None:
            continue
        crossings.append(
            TrustBoundaryCrossing(
                authority_relationship_id=after.relationship_id,
                family=family,
                before=old.classification,
                after=new.classification,
                direction=direction,
            )
        )

    if left.control.resolution != "unknown" and right.control.resolution != "unknown":
        direction = _control_direction(
            left.control.classification,
            right.control.classification,
        )
        if direction is not None:
            crossings.append(
                TrustBoundaryCrossing(
                    authority_relationship_id=after.relationship_id,
                    family="control",
                    before=left.control.classification,
                    after=right.control.classification,
                    direction=direction,
                )
            )

    return sorted(
        crossings,
        key=lambda item: (
            item.family,
            item.before,
            item.after,
            item.direction,
        ),
    )


def trust_boundary_report(
    relationships: list[EffectiveAuthorityRelationship],
) -> dict[str, Any]:
    classifications = [
        classify_relationship(relationship)
        for relationship in relationships
    ]
    classifications = sorted(
        classifications,
        key=lambda item: (
            item.agent,
            item.target_kind,
            item.target_name,
            item.authority_relationship_id,
        ),
    )
    return {
        "schema_version": TRUST_BOUNDARY_SCHEMA_VERSION,
        "runtime_effectiveness": "not_verified",
        "summary": {
            "relationships": len(classifications),
            "unknown_mutation": sum(item.mutation.resolution == "unknown" for item in classifications),
            "unknown_network": sum(item.network.resolution == "unknown" for item in classifications),
            "unknown_identity": sum(item.identity.resolution == "unknown" for item in classifications),
            "unknown_control": sum(item.control.resolution == "unknown" for item in classifications),
            "unknown_mcp_scope": sum(
                item.mcp_scope.resolution == "unknown" for item in classifications
            ),
        },
        "relationships": [item.as_dict() for item in classifications],
    }
