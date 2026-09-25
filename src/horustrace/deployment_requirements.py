"""Cross-layer deployment evidence for positive required cloud authority.

These rules intentionally require corroborating application and infrastructure evidence.
They only add positive minimum requirements; they never claim that the resulting role
set is a complete least-privilege baseline.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from horustrace.deployment_evidence import DeploymentEvidenceBundle
from horustrace.limits import MAX_FILE_SIZE_BYTES, MAX_FILES_VISITED
from horustrace.models import Graph

_IGNORED_DIRS = {
    ".git",
    ".terraform",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
}

_RESOURCE_RE = re.compile(
    r'\bresource\s+"(?P<kind>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{'
)
_ACCOUNT_ID_RE = re.compile(r'\baccount_id\s*=\s*"([^"]+)"')
_SERVICE_ACCOUNT_RE = re.compile(r"\bservice_account\s*=\s*([^\n#]+)")
_SERVICE_ACCOUNT_REF_RE = re.compile(
    r"google_service_account\.([A-Za-z0-9_-]+)\.email"
)
_MOUNT_RE = re.compile(r'\bmount_path\s*=\s*"/cloudsql/?(?:")')
_DATABASE_URL_NAME_RE = re.compile(
    r'\bname\s*=\s*"DATABASE_URL"', re.IGNORECASE
)

_DATABASE_CONNECT_CALLS = {
    "asyncpg.connect",
    "asyncpg.create_pool",
    "psycopg.connect",
    "psycopg2.connect",
    "sqlalchemy.create_engine",
    "sqlalchemy.ext.asyncio.create_async_engine",
    "create_engine",
    "create_async_engine",
}


@dataclass(frozen=True, slots=True)
class DeploymentRequirementEnrichment:
    provider: str
    rules_evaluated: tuple[str, ...]
    application_database_evidence: int
    cloud_sql_workloads: int
    matched_agents: int
    required_roles_added: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "rules_evaluated": list(self.rules_evaluated),
            "application_database_evidence": self.application_database_evidence,
            "cloud_sql_workloads": self.cloud_sql_workloads,
            "matched_agents": self.matched_agents,
            "required_roles_added": self.required_roles_added,
            "runtime_effectiveness": "not_verified",
        }


def _safe_files(root: Path, suffix: str) -> list[Path]:
    files: list[Path] = []
    visited = 0
    for candidate in root.rglob("*"):
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            continue
        if any(part in _IGNORED_DIRS for part in relative.parts):
            continue
        if not candidate.is_file():
            continue
        visited += 1
        if visited > MAX_FILES_VISITED:
            break
        if candidate.suffix.lower() != suffix:
            continue
        try:
            if candidate.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue
        files.append(candidate)
    return sorted(files)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _references_database_url(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id.upper() == "DATABASE_URL":
            return True
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            value = child.value
            if "/cloudsql/" in value or value.upper() == "DATABASE_URL":
                return True
        if isinstance(child, ast.Call):
            called = _call_name(child.func).lower()
            if called in {"os.getenv", "os.environ.get"} and child.args:
                value = child.args[0]
                if (
                    isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                    and value.value.upper() == "DATABASE_URL"
                ):
                    return True
    return False


def _application_database_evidence(root: Path) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for path in _safe_files(root, ".py"):
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            called = _call_name(node.func).lower()
            if not any(
                called == candidate or called.endswith(f".{candidate}")
                for candidate in _DATABASE_CONNECT_CALLS
            ):
                continue
            if not _references_database_url(node):
                continue
            try:
                relative = path.relative_to(root)
            except ValueError:
                relative = path
            item = {
                "kind": "database_connect",
                "environment_variable": "DATABASE_URL",
                "call": called,
                "path": str(relative),
                "line": getattr(node, "lineno", 1),
            }
            if item not in evidence:
                evidence.append(item)
    return evidence


def _matching_brace(text: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = opening
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""

        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue

        if char in {'"', "'"}:
            quote = char
            index += 1
            continue
        if char == "#":
            line_comment = True
            index += 1
            continue
        if char == "/" and nxt == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            block_comment = True
            index += 2
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _resource_blocks(
    text: str,
    *,
    kind: str | None = None,
) -> list[tuple[str, str, str, int]]:
    result: list[tuple[str, str, str, int]] = []
    for match in _RESOURCE_RE.finditer(text):
        resource_kind = match.group("kind")
        if kind is not None and resource_kind != kind:
            continue
        opening = match.end() - 1
        closing = _matching_brace(text, opening)
        if closing is None:
            continue
        line = text.count("\n", 0, match.start()) + 1
        result.append(
            (
                resource_kind,
                match.group("name"),
                text[opening + 1 : closing],
                line,
            )
        )
    return result


def _terraform_cloud_sql_workloads(root: Path) -> list[dict[str, Any]]:
    service_accounts: dict[str, str] = {}
    terraform_docs: list[tuple[Path, str]] = []
    for path in _safe_files(root, ".tf"):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        terraform_docs.append((path, text))
        for _, name, block, _ in _resource_blocks(
            text,
            kind="google_service_account",
        ):
            account = _ACCOUNT_ID_RE.search(block)
            if account:
                service_accounts[name] = account.group(1)

    result: list[dict[str, Any]] = []
    for path, text in terraform_docs:
        for _, resource_name, block, line in _resource_blocks(
            text,
            kind="google_cloud_run_v2_service",
        ):
            if "cloud_sql_instance" not in block:
                continue
            if not _MOUNT_RE.search(block):
                continue
            if not _DATABASE_URL_NAME_RE.search(block):
                continue
            if "/cloudsql/" not in block:
                continue

            service_match = _SERVICE_ACCOUNT_RE.search(block)
            if service_match is None:
                continue
            service_expression = service_match.group(1).strip()
            account_id: str | None = None

            literal = re.fullmatch(r'"([^"]+)"', service_expression)
            if literal and "@" in literal.group(1):
                account_id = literal.group(1).split("@", 1)[0]
            else:
                ref = _SERVICE_ACCOUNT_REF_RE.search(service_expression)
                if ref:
                    account_id = service_accounts.get(ref.group(1))

            if not account_id:
                continue

            try:
                relative = path.relative_to(root)
            except ValueError:
                relative = path
            item = {
                "resource": f"google_cloud_run_v2_service.{resource_name}",
                "service_account_account_id": account_id,
                "path": str(relative),
                "line": line,
                "cloud_sql_socket_mount": "/cloudsql",
                "environment_variable": "DATABASE_URL",
            }
            if item not in result:
                result.append(item)
    return result


def _workload_local_part(identity: str) -> str | None:
    value = identity.strip()
    if value.lower().startswith("serviceaccount:"):
        value = value.split(":", 1)[1]
    if "@" not in value:
        return None
    local = value.split("@", 1)[0].strip()
    return local or None


def enrich_cross_layer_required_authority(
    graph: Graph,
    application_root: Path,
    authority_source: Path,
    bundle: DeploymentEvidenceBundle,
) -> DeploymentRequirementEnrichment:
    """Add high-confidence positive deployment requirements to matching agents."""
    rule = "gcp.cloud_run.cloud_sql_socket"
    if bundle.provider != "gcp":
        return DeploymentRequirementEnrichment(
            provider=bundle.provider,
            rules_evaluated=(rule,),
            application_database_evidence=0,
            cloud_sql_workloads=0,
            matched_agents=0,
            required_roles_added=0,
        )

    app_root = application_root if application_root.is_dir() else application_root.parent
    app_evidence = _application_database_evidence(app_root)
    cloud_sql = _terraform_cloud_sql_workloads(authority_source)

    agents = {agent.name: agent for agent in graph.agents}
    matched_agents: set[str] = set()
    roles_added = 0

    if app_evidence and cloud_sql:
        for workload in bundle.workloads:
            if workload.agent is None or workload.agent not in agents:
                continue
            local_part = _workload_local_part(workload.identity)
            if local_part is None:
                continue
            matching_wiring = [
                item
                for item in cloud_sql
                if item["service_account_account_id"] == local_part
            ]
            if not matching_wiring:
                continue

            agent = agents[workload.agent]
            required = agent.metadata.setdefault(
                "deployment_required_authority",
                {
                    "provider": "gcp",
                    "roles": [],
                    "permissions": [],
                    "roles_complete": False,
                    "permissions_complete": False,
                    "evidence": [],
                },
            )
            roles = set(required.get("roles") or [])
            before = len(roles)
            roles.add("roles/cloudsql.client")
            roles_added += len(roles) - before
            required["roles"] = sorted(roles)
            required["roles_complete"] = False

            evidence = list(required.get("evidence") or [])
            item = {
                "rule": rule,
                "provider": "gcp",
                "role": "roles/cloudsql.client",
                "workload_id": workload.workload_id,
                "agent": workload.agent,
                "identity": workload.identity,
                "application": app_evidence,
                "infrastructure": matching_wiring,
            }
            if item not in evidence:
                evidence.append(item)
            required["evidence"] = evidence
            matched_agents.add(workload.agent)

    return DeploymentRequirementEnrichment(
        provider=bundle.provider,
        rules_evaluated=(rule,),
        application_database_evidence=len(app_evidence),
        cloud_sql_workloads=len(cloud_sql),
        matched_agents=len(matched_agents),
        required_roles_added=roles_added,
    )
