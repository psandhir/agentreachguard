"""Build independent source-only reference truth for the 2026 real-world study.

This program deliberately does not import HorusTrace and never installs, imports, or
executes a target repository. It fetches exact target SHAs, performs two source-review
passes (structural AST/JSON plus lexical cross-check), writes conservative reference
assertions, and locks the reference set before baseline execution.
"""
from __future__ import annotations

TRUTH_WORKFLOW_TRIGGER_AFTER_HARNESS_MERGE = True


import argparse
import ast
import concurrent.futures
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STUDY = "real-world-agent-security-2026"
LOCK_DATE = "2026-09-26"
MAX_FILES = 100
MAX_BYTES = 3_000_000
CLONE_TIMEOUT = 180
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".ipynb"}
DEPLOY_SUFFIXES = {".tf", ".yaml", ".yml", ".json", ".sh", ".md"}
AGENT_CTORS = {
    "Agent", "LlmAgent", "SequentialAgent", "ParallelAgent", "LoopAgent",
    "RemoteA2aAgent", "Workflow", "FastAgent", "StateGraph",
    "create_react_agent", "create_agent", "create_deep_agent",
    "create_supervisor", "create_swarm",
}
MCP_MARKERS = ("MCPServer", "McpServer", "MCPToolset", "McpToolset")
TOOL_DECORATORS = {"tool", "tool_plain", "function_tool"}
DELEGATION_KEYS = {"sub_agents", "subagents", "handoffs"}
DYNAMIC_MARKERS = (
    "eval(", "exec(", "getattr(", "__import__(", "importlib.",
    "globals()[", "locals()[",
)


@dataclass(frozen=True)
class Fact:
    name: str
    path: str
    line: int
    variable: str | None = None
    owner: str | None = None
    kind: str | None = None
    aliases: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "path": self.path,
            "line": self.line,
        }
        if self.variable:
            result["variable"] = self.variable
        if self.owner:
            result["owner"] = self.owner
        if self.kind:
            result["kind"] = self.kind
        if self.aliases:
            result["aliases"] = list(self.aliases)
        return result


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def run(command: list[str], *, timeout: int = CLONE_TIMEOUT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env={**__import__("os").environ, "GIT_TERMINAL_PROMPT": "0"},
    )


def fetch_case(workspace: Path, case: dict[str, Any], *, tier_c: bool) -> tuple[Path | None, str | None]:
    target = workspace / case["case_id"]
    target.mkdir(parents=True, exist_ok=True)
    commands = [
        ["git", "init", "-q", str(target)],
        ["git", "-C", str(target), "remote", "add", "origin",
         f"https://github.com/{case['repo']}.git"],
        ["git", "-C", str(target), "fetch", "--quiet", "--depth=1",
         "--filter=blob:none", "origin", case["sha"]],
    ]
    for command in commands:
        result = run(command)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-1000:]
            return None, f"fetch_failed:{detail}"

    app_path = Path(case["application_path"])
    if not tier_c:
        sparse = app_path if app_path.suffix == "" else app_path.parent
        pattern = sparse.as_posix() if sparse.as_posix() not in {"", "."} else "/*"
        for command in (
            ["git", "-C", str(target), "sparse-checkout", "init", "--no-cone"],
            ["git", "-C", str(target), "sparse-checkout", "set", "--no-cone", pattern],
        ):
            result = run(command, timeout=60)
            if result.returncode != 0:
                # Sparse checkout is an optimisation, never a selection rule.
                run(["git", "-C", str(target), "sparse-checkout", "disable"], timeout=60)
                break

    result = run(["git", "-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-1000:]
        return None, f"checkout_failed:{detail}"
    revision = run(["git", "-C", str(target), "rev-parse", "HEAD"], timeout=30)
    if revision.returncode != 0 or revision.stdout.strip() != case["sha"]:
        return None, "frozen_sha_mismatch"
    if not (target / app_path).exists():
        return target, f"application_path_missing:{case['application_path']}"
    return target, None


def notebook_code(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return ""
    cells = data.get("cells", []) if isinstance(data, dict) else []
    parts: list[str] = []
    for cell in cells:
        if isinstance(cell, dict) and cell.get("cell_type") == "code":
            src = cell.get("source", [])
            if isinstance(src, list):
                parts.append("".join(str(x) for x in src))
            elif isinstance(src, str):
                parts.append(src)
    return "\n\n".join(parts)


def collect_sources(root: Path, application_path: str) -> tuple[list[tuple[str, str]], list[str]]:
    selected = root / application_path
    scope = selected if selected.is_dir() else selected.parent
    candidates: list[Path]
    if selected.is_file():
        candidates = [selected]
        # Include sibling application modules in the selected bounded application directory.
        candidates.extend(
            p for p in scope.rglob("*")
            if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES and p != selected
        )
    else:
        candidates = [
            p for p in scope.rglob("*")
            if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES
        ]
    candidates = sorted(dict.fromkeys(candidates), key=lambda p: p.as_posix())
    sources: list[tuple[str, str]] = []
    diagnostics: list[str] = []
    total = 0
    for path in candidates[:MAX_FILES]:
        try:
            text = notebook_code(path) if path.suffix.lower() == ".ipynb" else path.read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError as exc:
            diagnostics.append(f"read_failed:{path.name}:{exc.__class__.__name__}")
            continue
        encoded = len(text.encode("utf-8", errors="replace"))
        if total + encoded > MAX_BYTES:
            diagnostics.append("source_scope_byte_limit_reached")
            break
        total += encoded
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        sources.append((rel, text))
    if len(candidates) > MAX_FILES:
        diagnostics.append("source_scope_file_limit_reached")
    if not sources:
        diagnostics.append("no_readable_application_source")
    return sources, diagnostics


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = call_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


def literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def list_names(node: ast.AST | None) -> list[str]:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return []
    result: list[str] = []
    for item in node.elts:
        if isinstance(item, ast.Name):
            result.append(item.id)
        elif isinstance(item, ast.Constant) and isinstance(item.value, str):
            result.append(item.value)
        elif isinstance(item, ast.Attribute):
            result.append(item.attr)
        elif isinstance(item, ast.Call):
            name = call_name(item.func)
            if name.endswith(".as_tool") and isinstance(item.func, ast.Attribute):
                owner = call_name(item.func.value)
                if owner:
                    result.append(owner)
            elif name:
                result.append(name.split(".")[-1])
    return result


def assign_targets(node: ast.Assign | ast.AnnAssign) -> list[str]:
    raw = node.targets if isinstance(node, ast.Assign) else [node.target]
    result: list[str] = []
    for item in raw:
        if isinstance(item, ast.Name):
            result.append(item.id)
        elif isinstance(item, (ast.Tuple, ast.List)):
            result.extend(x.id for x in item.elts if isinstance(x, ast.Name))
    return result


def kw(call: ast.Call, name: str) -> ast.AST | None:
    for item in call.keywords:
        if item.arg == name:
            return item.value
    return None


def extract_python(path: str, text: str) -> tuple[list[Fact], list[Fact], list[Fact], list[dict[str, Any]], list[str]]:
    agents: list[Fact] = []
    tools: list[Fact] = []
    mcps: list[Fact] = []
    delegations: list[dict[str, Any]] = []
    diagnostics: list[str] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return agents, tools, mcps, delegations, ["python_ast_parse_failed"]

    variable_to_name: dict[str, str] = {}
    pending_delegations: list[tuple[str, str, int, str]] = []

    for node in ast.walk(tree):
        value: ast.AST | None = None
        targets: list[str] = []
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = assign_targets(node)
            value = node.value
        if targets and isinstance(value, ast.Call):
            full = call_name(value.func)
            ctor = full.split(".")[-1]
            for variable in targets:
                if ctor in AGENT_CTORS:
                    declared = literal_string(kw(value, "name")) or variable
                    aliases = tuple(sorted({variable, declared} - {declared}))
                    agents.append(
                        Fact(
                            name=declared,
                            variable=variable,
                            path=path,
                            line=getattr(node, "lineno", 1),
                            kind=ctor,
                            aliases=aliases,
                        )
                    )
                    variable_to_name[variable] = declared
                    for key in DELEGATION_KEYS:
                        for target in list_names(kw(value, key)):
                            pending_delegations.append(
                                (variable, target, getattr(node, "lineno", 1), key)
                            )
                    for tool_name in list_names(kw(value, "tools")):
                        tools.append(
                            Fact(
                                name=tool_name,
                                owner=variable,
                                path=path,
                                line=getattr(node, "lineno", 1),
                                kind="agent_tool_reference",
                            )
                        )
                        if tool_name in variable_to_name:
                            pending_delegations.append(
                                (variable, tool_name, getattr(node, "lineno", 1), "agent_as_tool")
                            )
                if any(marker.lower() in ctor.lower() for marker in MCP_MARKERS):
                    declared = literal_string(kw(value, "name")) or variable
                    mcps.append(
                        Fact(
                            name=declared,
                            variable=variable,
                            path=path,
                            line=getattr(node, "lineno", 1),
                            kind=ctor,
                            aliases=(variable,) if declared != variable else (),
                        )
                    )

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                deco = decorator.func if isinstance(decorator, ast.Call) else decorator
                full = call_name(deco)
                last = full.split(".")[-1]
                if last in TOOL_DECORATORS:
                    owner = full.rsplit(".", 1)[0] if "." in full and last in {"tool", "tool_plain"} else None
                    tools.append(
                        Fact(
                            name=node.name,
                            owner=owner,
                            path=path,
                            line=node.lineno,
                            kind=f"decorator:{last}",
                        )
                    )
                if last in {"agent", "orchestrator", "chain", "parallel"} and "." in full:
                    declared = (
                        literal_string(kw(decorator, "name")) if isinstance(decorator, ast.Call) else None
                    ) or node.name
                    agents.append(
                        Fact(
                            name=declared,
                            variable=node.name,
                            path=path,
                            line=node.lineno,
                            kind=f"decorator:{last}",
                            aliases=(node.name,) if declared != node.name else (),
                        )
                    )
                    variable_to_name[node.name] = declared

        if isinstance(node, ast.Call):
            full = call_name(node.func)
            if full.endswith(".add_node") and node.args:
                node_name = literal_string(node.args[0])
                if node_name:
                    agents.append(
                        Fact(
                            name=node_name,
                            variable=node_name,
                            path=path,
                            line=getattr(node, "lineno", 1),
                            kind="workflow_node",
                        )
                    )

    for source_var, target_var, line, kind in pending_delegations:
        source = variable_to_name.get(source_var, source_var)
        target = variable_to_name.get(target_var, target_var)
        delegations.append(
            {
                "source": source,
                "target": target,
                "path": path,
                "line": line,
                "kind": kind,
                "source_variable": source_var,
                "target_variable": target_var,
            }
        )
    return agents, tools, mcps, delegations, diagnostics


ASSIGN_RE = re.compile(
    r"(?m)^\s*(?:const|let|var)?\s*([A-Za-z_]\w*)\s*=\s*(?:new\s+)?"
    r"(Agent|LlmAgent|SequentialAgent|ParallelAgent|LoopAgent|RemoteA2aAgent|Workflow|"
    r"FastAgent|StateGraph|create_react_agent|create_agent|create_deep_agent|"
    r"create_supervisor|create_swarm)\s*\("
)
MCP_RE = re.compile(
    r"(?m)^\s*(?:const|let|var)?\s*([A-Za-z_]\w*)\s*=\s*(?:new\s+)?"
    r"([A-Za-z_]\w*(?:MCP|Mcp)\w*(?:Server|Toolset)\w*)\s*\("
)
TOOL_RE = re.compile(r"(?m)^\s*(?:@(?:\w+\.)?(?:tool|tool_plain|function_tool)\b.*\n\s*)?(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")


def line_of(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def lexical_extract(path: str, text: str) -> tuple[list[Fact], list[Fact], list[Fact]]:
    agents = [
        Fact(name=m.group(1), variable=m.group(1), path=path, line=line_of(text, m.start()), kind=m.group(2))
        for m in ASSIGN_RE.finditer(text)
    ]
    mcps = [
        Fact(name=m.group(1), variable=m.group(1), path=path, line=line_of(text, m.start()), kind=m.group(2))
        for m in MCP_RE.finditer(text)
    ]
    tools: list[Fact] = []
    if Path(path).suffix.lower() == ".py":
        for m in re.finditer(
            r"(?m)^\s*@(?:[A-Za-z_]\w*\.)?(tool|tool_plain|function_tool)(?:\([^)]*\))?\s*\n"
            r"\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(",
            text,
        ):
            tools.append(Fact(name=m.group(2), path=path, line=line_of(text, m.start()), kind=f"lexical:{m.group(1)}"))
    return agents, tools, mcps


def dedupe_facts(items: list[Fact]) -> list[Fact]:
    seen: set[tuple[str, str, int, str | None]] = set()
    out: list[Fact] = []
    for item in sorted(items, key=lambda x: (x.path, x.line, x.name, x.kind or "")):
        key = (item.name, item.path, item.line, item.owner)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def facts_match(left: Fact, right: Fact) -> bool:
    names = {left.name, left.variable or "", *left.aliases}
    other = {right.name, right.variable or "", *right.aliases}
    return bool(names & other) and left.path == right.path and abs(left.line - right.line) <= 4


def build_reference(sources: list[tuple[str, str]], diagnostics: list[str]) -> dict[str, Any]:
    ast_agents: list[Fact] = []
    ast_tools: list[Fact] = []
    ast_mcps: list[Fact] = []
    delegations: list[dict[str, Any]] = []
    lexical_agents: list[Fact] = []
    lexical_tools: list[Fact] = []
    lexical_mcps: list[Fact] = []
    dynamic = False
    python_parse_failures = 0
    code_suffixes: set[str] = set()

    for path, text in sources:
        suffix = Path(path).suffix.lower()
        code_suffixes.add(suffix)
        dynamic = dynamic or any(marker in text for marker in DYNAMIC_MARKERS)
        if suffix in {".py", ".ipynb"}:
            a, t, m, d, diag = extract_python(path, text)
            ast_agents.extend(a)
            ast_tools.extend(t)
            ast_mcps.extend(m)
            delegations.extend(d)
            python_parse_failures += diag.count("python_ast_parse_failed")
            diagnostics.extend(f"{path}:{item}" for item in diag)
        la, lt, lm = lexical_extract(path, text)
        lexical_agents.extend(la)
        lexical_tools.extend(lt)
        lexical_mcps.extend(lm)

    agents = dedupe_facts(ast_agents + [
        item for item in lexical_agents
        if not any(facts_match(item, other) for other in ast_agents)
    ])
    tools = dedupe_facts(ast_tools + [
        item for item in lexical_tools
        if not any(facts_match(item, other) for other in ast_tools)
    ])
    mcps = dedupe_facts(ast_mcps + [
        item for item in lexical_mcps
        if not any(facts_match(item, other) for other in ast_mcps)
    ])

    ast_lexical_disagreement = any(
        not any(facts_match(item, other) for other in ast_agents)
        for item in lexical_agents
    )
    if ast_lexical_disagreement:
        diagnostics.append("agent_ast_lexical_crosscheck_disagreement")
    if dynamic:
        diagnostics.append("dynamic_source_constructs_detected")

    all_structured = bool(sources) and code_suffixes <= {".py", ".ipynb"}
    complete_agents = all_structured and python_parse_failures == 0 and not dynamic and not ast_lexical_disagreement
    complete_tools = complete_agents and "source_scope_file_limit_reached" not in diagnostics and "source_scope_byte_limit_reached" not in diagnostics
    complete_mcp = complete_agents
    complete_delegation = complete_agents

    return {
        "agents": agents,
        "tools": tools,
        "mcps": mcps,
        "delegations": delegations,
        "unresolved": sorted(set(diagnostics)),
        "completeness": {
            "agent_entities": complete_agents,
            "tools": complete_tools,
            "mcp_servers": complete_mcp,
            "delegation_edges": complete_delegation,
        },
    }


IDENTITY_RE = re.compile(
    r"\b[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\.iam\.gserviceaccount\.com\b"
)
GCP_ROLE_RE = re.compile(r"\broles/[A-Za-z0-9_.-]+\b")
AWS_ROLE_RE = re.compile(r"\barn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+\b")


def extract_deployment(root: Path) -> dict[str, Any]:
    identities: list[dict[str, Any]] = []
    roles: list[dict[str, Any]] = []
    files_reviewed = 0
    for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
        if not path.is_file() or path.suffix.lower() not in DEPLOY_SUFFIXES:
            continue
        if any(part in {".git", "node_modules", "vendor", ".venv", "venv"} for part in path.parts):
            continue
        files_reviewed += 1
        if files_reviewed > 400:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            rel = path.relative_to(root).as_posix()
        except OSError:
            continue
        for regex, provider in ((IDENTITY_RE, "gcp"), (AWS_ROLE_RE, "aws")):
            for match in regex.finditer(text):
                identities.append(
                    {
                        "identity": match.group(0),
                        "provider": provider,
                        "path": rel,
                        "line": line_of(text, match.start()),
                    }
                )
        for match in GCP_ROLE_RE.finditer(text):
            roles.append(
                {
                    "role": match.group(0),
                    "provider": "gcp",
                    "path": rel,
                    "line": line_of(text, match.start()),
                }
            )
    def unique(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
        seen: set[tuple[str, str]] = set()
        out: list[dict[str, Any]] = []
        for item in items:
            marker = (str(item[key]), str(item["path"]))
            if marker not in seen:
                seen.add(marker)
                out.append(item)
        return out
    return {
        "runtime_effectiveness": "not_verified",
        "files_reviewed": min(files_reviewed, 400),
        "workload_or_deployer_identities": unique(identities, "identity"),
        "declared_roles": unique(roles, "role"),
        "unresolved": [
            "repository evidence cannot establish live runtime effectiveness",
            "identity-to-agent binding is scored only when source evidence is explicit",
        ],
    }


def assertion(
    assertion_id: str,
    subject: str,
    predicate: str,
    evidence_path: str,
    line: int,
    rationale: str,
    *,
    obj: Any = None,
    tier: str = "A",
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "assertion_id": assertion_id,
        "subject": subject,
        "predicate": predicate,
        "expected_state": "present",
        "evidence": [
            {
                "path": evidence_path,
                "line": max(1, line),
                "rationale": rationale,
            }
        ],
        "rationale": rationale,
        "tier": tier,
    }
    if obj is not None:
        value["object"] = obj
    return value


def build_truth(
    case: dict[str, Any],
    candidate: dict[str, Any],
    root: Path | None,
    fetch_error: str | None,
    *,
    tier_b: bool,
    tier_c: bool,
) -> dict[str, Any]:
    diagnostics: list[str] = []
    if fetch_error:
        diagnostics.append(fetch_error)
    sources: list[tuple[str, str]] = []
    if root is not None and not fetch_error:
        sources, diagnostics = collect_sources(root, case["application_path"])
    ref = build_reference(sources, diagnostics)

    assertions: list[dict[str, Any]] = []
    counter = 1
    for fact in ref["agents"]:
        assertions.append(assertion(
            f"{case['case_id'].upper()}.A{counter:03d}",
            fact.name, "explicit_agent_entity", fact.path, fact.line,
            "Independent source review found an explicit agent/workflow construction.",
            obj=case["framework_stratum"],
        ))
        counter += 1
    for fact in ref["tools"]:
        assertions.append(assertion(
            f"{case['case_id'].upper()}.A{counter:03d}",
            fact.owner or case["case_id"], "explicit_tool_reference", fact.path, fact.line,
            "Independent source review found an explicit tool definition or bound tool reference.",
            obj=fact.name,
        ))
        counter += 1
    for fact in ref["mcps"]:
        assertions.append(assertion(
            f"{case['case_id'].upper()}.A{counter:03d}",
            fact.owner or case["case_id"], "explicit_mcp_server", fact.path, fact.line,
            "Independent source review found explicit MCP server/toolset construction.",
            obj=fact.name,
        ))
        counter += 1
    for edge in ref["delegations"]:
        assertions.append(assertion(
            f"{case['case_id'].upper()}.A{counter:03d}",
            edge["source"], "delegates_to", edge["path"], edge["line"],
            "Independent source review found an explicit sub-agent/handoff relationship.",
            obj=edge["target"],
        ))
        counter += 1

    tier_b_doc: dict[str, Any] | None = None
    if tier_b:
        relations: list[dict[str, Any]] = []
        agent_aliases: dict[str, str] = {}
        for fact in ref["agents"]:
            if fact.variable:
                agent_aliases[fact.variable] = fact.name
            agent_aliases[fact.name] = fact.name
        for fact in ref["tools"]:
            if fact.owner and fact.owner in agent_aliases:
                relation = {
                    "agent": agent_aliases[fact.owner],
                    "target_kind": "tool",
                    "target_name": fact.name,
                    "path": fact.path,
                    "line": fact.line,
                }
                relations.append(relation)
                assertions.append(assertion(
                    f"{case['case_id'].upper()}.B{len(relations):03d}",
                    relation["agent"], "can_invoke", fact.path, fact.line,
                    "The tool is explicitly bound to the source-reviewed agent.",
                    obj={"kind": "tool", "name": fact.name}, tier="B",
                ))
        dangerous = {
            "process_execution", "filesystem_write", "external_write_or_network",
            "external_write_or_transaction_semantics", "sensitive_resource_access",
            "multiple_trust_boundaries", "mcp_usage", "approval_controls",
            "identity_and_credential_boundaries", "browser_or_web_access",
            "state_mutation", "sms_side_effect", "enterprise_mutation_surface",
        }
        signals = list(candidate.get("screening", {}).get("tier_b", {}).get("signals", []))
        tier_b_doc = {
            "review_method": "independent dual-pass source reference",
            "eligibility_signals": signals,
            "authority_relationships": relations,
            "security_relevant_signals": sorted(set(signals) & dangerous),
            "attack_path_reference": {
                "structural_only": True,
                "runtime_exploitability": "not_verified",
                "source_supported_authority_pairs": [
                    {"agent": x["agent"], "target_kind": x["target_kind"], "target_name": x["target_name"]}
                    for x in relations
                ],
            },
            "limitations": [
                "reference evaluates static structural validity, not runtime exploitability",
                "dynamic authority is unresolved unless explicit in pinned source",
            ],
        }

    tier_c_doc: dict[str, Any] | None = None
    if tier_c:
        deployment = extract_deployment(root) if root is not None else {
            "runtime_effectiveness": "not_verified",
            "files_reviewed": 0,
            "workload_or_deployer_identities": [],
            "declared_roles": [],
            "unresolved": ["source fetch unavailable for deployment review"],
        }
        tier_c_doc = {
            "review_method": "repository-declared deployment/IAM source review",
            **deployment,
        }
        c_index = 1
        for item in deployment.get("workload_or_deployer_identities", []):
            assertions.append(assertion(
                f"{case['case_id'].upper()}.C{c_index:03d}",
                case["case_id"], "declares_identity", item["path"], item["line"],
                "Repository deployment/IAM source explicitly declares this identity.",
                obj=item["identity"], tier="C",
            ))
            c_index += 1
        for item in deployment.get("declared_roles", []):
            assertions.append(assertion(
                f"{case['case_id'].upper()}.C{c_index:03d}",
                case["case_id"], "declares_role", item["path"], item["line"],
                "Repository deployment/IAM source explicitly declares this role.",
                obj=item["role"], tier="C",
            ))
            c_index += 1

    truth: dict[str, Any] = {
        "schema_version": 1,
        "study": STUDY,
        "case_id": case["case_id"],
        "source_reference": {
            "repo": case["repo"],
            "sha": case["sha"],
            "application_path": case["application_path"],
            "framework_stratum": case["framework_stratum"],
            "method_version": "source-reference-v1",
            "automated_reference": True,
            "human_dual_review": False,
            "note": (
                "Two independent automated source-review passes are used. This is not "
                "represented as human dual-review and is reported as a study limitation."
            ),
        },
        "truth_lock": {
            "reviewed": True,
            "horustrace_output_seen": False,
            "locked_at": LOCK_DATE,
            "reviewers": [
                "independent-source-structural-pass-v1",
                "independent-source-lexical-crosscheck-v1",
            ],
        },
        "tier_a": {
            "frameworks": [case["framework_stratum"]],
            "agent_roots": [x.as_dict() for x in ref["agents"]],
            "tools": [x.as_dict() for x in ref["tools"]],
            "mcp_servers": [x.as_dict() for x in ref["mcps"]],
            "delegation_edges": ref["delegations"],
            "unresolved": ref["unresolved"],
            "reference_completeness": ref["completeness"],
            "source_files_reviewed": len(sources),
        },
        "assertions": assertions,
    }
    if tier_b:
        truth["tier_b"] = tier_b_doc
    if tier_c:
        truth["tier_c"] = tier_c_doc
    return truth


def generate(root: Path, workers: int) -> dict[str, Any]:
    cohort_path = root / "cohort.json"
    candidates_path = root / "candidates.json"
    cohort = load_json(cohort_path)
    candidates = load_json(candidates_path)
    candidate_by_repo = {
        item["repo"]: item for item in candidates.get("candidates", [])
        if isinstance(item, dict) and item.get("decision") == "include"
    }
    cases = cohort.get("cases", [])
    tier_b_ids = set(cohort.get("tier_b_case_ids", []))
    tier_c_ids = set(cohort.get("tier_c_case_ids", []))
    out_dir = root / "ground-truth"
    out_dir.mkdir(parents=True, exist_ok=True)

    summaries: list[dict[str, Any]] = []
    workspace = Path(tempfile.mkdtemp(prefix="horustrace-real-world-truth-"))
    try:
        def one(case: dict[str, Any]) -> dict[str, Any]:
            tier_b = case["case_id"] in tier_b_ids
            tier_c = case["case_id"] in tier_c_ids
            checkout, error = fetch_case(workspace, case, tier_c=tier_c)
            candidate = candidate_by_repo[case["repo"]]
            truth = build_truth(
                case, candidate, checkout, error, tier_b=tier_b, tier_c=tier_c
            )
            destination = out_dir / f"{case['case_id']}.json"
            destination.write_text(
                json.dumps(truth, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return {
                "case_id": case["case_id"],
                "fetch_error": error,
                "assertions": len(truth["assertions"]),
                "agents": len(truth["tier_a"]["agent_roots"]),
                "tools": len(truth["tier_a"]["tools"]),
                "mcp_servers": len(truth["tier_a"]["mcp_servers"]),
                "delegation_edges": len(truth["tier_a"]["delegation_edges"]),
                "complete_agents": truth["tier_a"]["reference_completeness"]["agent_entities"],
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(one, case) for case in cases]
            for future in concurrent.futures.as_completed(futures):
                summaries.append(future.result())
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    summaries.sort(key=lambda item: item["case_id"])
    summary = {
        "cases": len(summaries),
        "fetch_failures": sum(bool(x["fetch_error"]) for x in summaries),
        "assertions": sum(x["assertions"] for x in summaries),
        "explicit_agent_entities": sum(x["agents"] for x in summaries),
        "explicit_tools": sum(x["tools"] for x in summaries),
        "explicit_mcp_servers": sum(x["mcp_servers"] for x in summaries),
        "explicit_delegation_edges": sum(x["delegation_edges"] for x in summaries),
        "agent_complete_cases": sum(bool(x["complete_agents"]) for x in summaries),
    }
    cohort["phase"] = "ground_truth_locked"
    cohort["ground_truth_locked"] = True
    cohort["ground_truth_reference"] = {
        "method_version": "source-reference-v1",
        "locked_at": LOCK_DATE,
        "automated_dual_pass": True,
        "human_dual_review": False,
        "summary": summary,
        "limitations": [
            "automated source reference is not a substitute for independent human dual adjudication",
            "precision is reported only where reference completeness is explicitly established",
            "dynamic/runtime constructs remain unresolved",
        ],
    }
    cohort_path.write_text(json.dumps(cohort, indent=2) + "\n", encoding="utf-8")
    (root / "ground-truth-summary.json").write_text(
        json.dumps({"schema_version": 1, "study": STUDY, "summary": summary, "cases": summaries}, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--root",
        type=Path,
        default=Path("research/real-world-agent-security-2026"),
    )
    p.add_argument("--workers", type=int, default=8)
    return p


def main() -> int:
    args = parser().parse_args()
    summary = generate(args.root, max(1, args.workers))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
