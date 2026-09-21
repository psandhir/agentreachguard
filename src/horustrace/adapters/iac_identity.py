from __future__ import annotations

import re
from pathlib import Path

from horustrace.models import Graph, Identity, SourceLocation

RESOURCE_RE = re.compile(r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
ROLE_RE = re.compile(r'\b(role|role_definition_name)\s*=\s*"([^"]+)"')
MEMBER_RE = re.compile(r'\b(member|principal_id)\s*=\s*"([^"]+)"')
SCOPE_RE = re.compile(r'\b(scope|project|resource_group_name)\s*=\s*"([^"]+)"')
ACTIONS_RE = re.compile(r'"Action"\s*:\s*(\[[^\]]*\]|"[^"]+")', re.DOTALL)
STRING_RE = re.compile(r'"([^"]+)"')


GCP_RESOURCES = {
    "google_project_iam_member",
    "google_project_iam_binding",
    "google_folder_iam_member",
    "google_folder_iam_binding",
    "google_organization_iam_member",
    "google_organization_iam_binding",
    "google_service_account_iam_member",
    "google_service_account_iam_binding",
}

AZURE_RESOURCES = {"azurerm_role_assignment"}
AWS_RESOURCES = {"aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy"}


def _blocks(text: str):
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        match = RESOURCE_RE.match(lines[i])
        if not match:
            i += 1
            continue
        resource_type, name = match.groups()
        start = i
        depth = lines[i].count("{") - lines[i].count("}")
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        yield resource_type, name, start + 1, "\n".join(lines[start:i])


def scan_terraform(path: Path) -> Graph:
    graph = Graph()
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return graph

    for resource_type, resource_name, line, block in _blocks(text):
        location = SourceLocation(path=path, line=line)
        if resource_type in GCP_RESOURCES:
            role = ROLE_RE.search(block)
            member = MEMBER_RE.search(block)
            scope = SCOPE_RE.search(block)
            graph.identities.append(
                Identity(
                    name=(member.group(2) if member else resource_name),
                    provider="gcp",
                    roles={role.group(2)} if role else set(),
                    resource_scope=scope.group(2) if scope else None,
                    location=location,
                    metadata={"terraform_resource": resource_type},
                )
            )
        elif resource_type in AZURE_RESOURCES:
            role = ROLE_RE.search(block)
            member = MEMBER_RE.search(block)
            scope = SCOPE_RE.search(block)
            graph.identities.append(
                Identity(
                    name=(member.group(2) if member else resource_name),
                    provider="azure",
                    roles={role.group(2)} if role else set(),
                    resource_scope=scope.group(2) if scope else None,
                    location=location,
                    metadata={"terraform_resource": resource_type},
                )
            )
        elif resource_type in AWS_RESOURCES:
            actions: set[str] = set()
            for action_match in ACTIONS_RE.finditer(block):
                actions.update(STRING_RE.findall(action_match.group(1)))
            graph.identities.append(
                Identity(
                    name=resource_name,
                    provider="aws",
                    permissions=actions,
                    resource_scope="*" if '"Resource": "*"' in block or '"Resource":"*"' in block else None,
                    location=location,
                    metadata={"terraform_resource": resource_type},
                )
            )

    return graph
