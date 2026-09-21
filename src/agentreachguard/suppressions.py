"""Stable finding fingerprints and narrow, expiring risk suppressions."""
from __future__ import annotations

import fnmatch
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from agentreachguard.models import Finding

SUPPRESSION_FILENAMES = {
    ".horustrace.suppressions.yaml",
    ".horustrace.suppressions.yml",
    ".agentreachguard.suppressions.yaml",
    ".agentreachguard.suppressions.yml",
}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RULE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")
FINGERPRINT_RE = re.compile(r"^arg-v1:[0-9a-f]{24}$")


class SuppressionError(ValueError):
    """A suppression file is invalid or unsafe to apply."""


class _UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in keys
                keys.add(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    None, None, "invalid mapping key", key_node.start_mark,
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None, None, "duplicate mapping key", key_node.start_mark,
                )
        return super().construct_mapping(node, deep=deep)


@dataclass(slots=True)
class Suppression:
    suppression_id: str
    reason: str
    expires: date
    fingerprint: str | None = None
    rule_id: str | None = None
    agent: str | None = None
    path: str | None = None


def fingerprint(finding: Finding, root: Path) -> str:
    path = ""
    if finding.location:
        try:
            path = finding.location.path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            path = finding.location.path.name
    parts = [finding.rule_id, finding.agent or "", path, *sorted(finding.evidence)]
    payload = unicodedata.normalize("NFC", "\0".join(parts))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"arg-v1:{digest}"


def _load(path: Path) -> list[Suppression]:
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueLoader)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SuppressionError(f"{path}: cannot read suppression configuration") from exc
    if (not isinstance(raw, dict) or type(raw.get("version")) is not int
            or raw.get("version") != 1):
        raise SuppressionError(f"{path}: suppression version must be 1")
    allowed_root = {"version", "suppressions"}
    if set(raw) - allowed_root:
        raise SuppressionError(f"{path}: unknown top-level suppression field")
    items = raw.get("suppressions")
    if not isinstance(items, list):
        raise SuppressionError(f"{path}: suppressions must be a list")
    result = []
    seen = set()
    allowed = {"id", "reason", "expires", "fingerprint", "rule_id", "agent", "path"}
    for index, item in enumerate(items):
        field = f"suppressions[{index}]"
        if not isinstance(item, dict) or set(item) - allowed:
            raise SuppressionError(f"{path}: {field} has invalid or unknown fields")
        if any(not isinstance(item.get(key), str) or not item[key].strip()
               for key in ("id", "reason")) or not item.get("expires"):
            raise SuppressionError(f"{path}: {field} requires nonempty id, reason and expires")
        if item["id"] in seen:
            raise SuppressionError(f"{path}: duplicate suppression id")
        seen.add(item["id"])
        if not ID_RE.fullmatch(item["id"]):
            raise SuppressionError(f"{path}: {field}.id has invalid characters")
        if len(item["reason"]) > 500 or any(ch in item["reason"] for ch in "\r\n"):
            raise SuppressionError(f"{path}: {field}.reason must be a single line up to 500 characters")
        optional = ("fingerprint", "rule_id", "agent", "path")
        if any(key in item and (not isinstance(item[key], str) or not item[key]) for key in optional):
            raise SuppressionError(f"{path}: {field} scopes must be nonempty strings")
        if not item.get("fingerprint") and not item.get("rule_id"):
            raise SuppressionError(f"{path}: {field} needs fingerprint or rule_id")
        if (item.get("rule_id") and not item.get("fingerprint")
                and not any(item.get(key) for key in ("agent", "path"))):
            raise SuppressionError(
                f"{path}: {field} rule_id suppression also needs agent or path scope"
            )
        if item.get("fingerprint") and not FINGERPRINT_RE.fullmatch(item["fingerprint"]):
            raise SuppressionError(f"{path}: {field}.fingerprint is not an arg-v1 fingerprint")
        if item.get("rule_id") and not RULE_RE.fullmatch(item["rule_id"]):
            raise SuppressionError(f"{path}: {field}.rule_id is invalid")
        if item.get("path"):
            scope = Path(item["path"])
            if scope.is_absolute() or ".." in scope.parts:
                raise SuppressionError(f"{path}: {field}.path must stay within the scan root")
        expiry_value = item["expires"]
        if type(expiry_value) is date:
            expiry = expiry_value
        elif isinstance(expiry_value, str):
            try:
                expiry = date.fromisoformat(expiry_value)
            except ValueError as exc:
                raise SuppressionError(f"{path}: {field} expires must be YYYY-MM-DD") from exc
        else:
            raise SuppressionError(f"{path}: {field} expires must be YYYY-MM-DD")
        result.append(Suppression(
            suppression_id=item["id"], reason=item["reason"], expires=expiry,
            fingerprint=item.get("fingerprint"), rule_id=item.get("rule_id"),
            agent=item.get("agent"), path=item.get("path"),
        ))
    return result


def _relative(finding: Finding, root: Path) -> str:
    if not finding.location:
        return ""
    try:
        return finding.location.path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return finding.location.path.name


def apply(
    findings: list[Finding], root: Path, path: Path | None,
) -> tuple[list[Finding], list[Finding], list[dict[str, Any]]]:
    for finding in findings:
        finding.fingerprint = fingerprint(finding, root)
    if path is None:
        return findings, [], []
    suppressions = _load(path)
    active = []
    diagnostics: list[dict[str, Any]] = []
    today = datetime.now(tz=UTC).date()
    for suppression in suppressions:
        if suppression.expires < today:
            diagnostics.append({
                "id": suppression.suppression_id, "status": "expired",
                "expires": suppression.expires.isoformat(), "reason": suppression.reason,
            })
        else:
            active.append(suppression)
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    matched = {s.suppression_id: 0 for s in active}
    for finding in findings:
        match = None
        relative = _relative(finding, root)
        for suppression in active:
            if suppression.fingerprint and suppression.fingerprint != finding.fingerprint:
                continue
            if suppression.rule_id and suppression.rule_id != finding.rule_id:
                continue
            if suppression.agent and suppression.agent != finding.agent:
                continue
            if suppression.path and not fnmatch.fnmatch(relative, suppression.path):
                continue
            match = suppression
            break
        if match:
            suppressed.append(finding)
            matched[match.suppression_id] += 1
        else:
            kept.append(finding)
    for suppression in active:
        count = matched[suppression.suppression_id]
        diagnostics.append({
            "id": suppression.suppression_id,
            "status": "matched" if count else "stale",
            "matches": count,
            "expires": suppression.expires.isoformat(),
            "reason": suppression.reason,
        })
    return kept, suppressed, diagnostics


def write_baseline(
    findings: list[Finding], root: Path, output: Path, reason: str, expires: date,
) -> None:
    items = []
    for index, finding in enumerate(findings, 1):
        value = finding.fingerprint or fingerprint(finding, root)
        items.append({
            "id": f"baseline-{index:04d}-{finding.rule_id.lower()}",
            "reason": reason,
            "expires": expires.isoformat(),
            "fingerprint": value,
            "rule_id": finding.rule_id,
        })
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump({"version": 1, "suppressions": items}, sort_keys=False),
                      encoding="utf-8")
