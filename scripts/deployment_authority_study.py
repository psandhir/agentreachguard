#!/usr/bin/env python3
"""Run the frozen HorusTrace v0.8 deployment-authority validation study.

The harness fetches public targets at exact commit SHAs and never imports, installs,
or executes target applications. HorusTrace itself is executed from the current
checkout against source files plus explicit local evidence.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SCHEMA_VERSION = 1
CLONE_TIMEOUT = 180
ANALYSIS_TIMEOUT = 300
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CASE_KINDS = {"natural", "mutation", "control"}
STATUSES = ("aligned", "excess_authority", "missing_authority", "mixed", "unresolved")


class StudyError(ValueError):
    """Raised when study inputs or execution violate the study contract."""


@dataclass(frozen=True, slots=True)
class RepoPin:
    repo: str
    sha: str
    path: str = "."


@dataclass(frozen=True, slots=True)
class StudyCase:
    case_id: str
    kind: str
    provider: str
    framework: str
    application: RepoPin
    infrastructure: RepoPin | None
    deployment_evidence: Path
    ground_truth: Path


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise StudyError(f"cannot load YAML {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StudyError(f"{path}: expected a mapping")
    return value


def _require_string(mapping: dict[str, Any], key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise StudyError(f"{where}.{key}: expected a non-empty string")
    return value.strip()


def _repo_pin(value: Any, where: str) -> RepoPin:
    if not isinstance(value, dict):
        raise StudyError(f"{where}: expected a mapping")
    repo = _require_string(value, "repo", where)
    sha = _require_string(value, "sha", where).lower()
    path = value.get("path", ".")
    if not isinstance(path, str) or not path.strip():
        raise StudyError(f"{where}.path: expected a non-empty string")
    if not SHA_RE.fullmatch(sha):
        raise StudyError(f"{where}.sha: expected an exact 40-character lowercase commit SHA")
    if repo.count("/") != 1 or repo.startswith("/") or repo.endswith("/"):
        raise StudyError(f"{where}.repo: expected owner/name")
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise StudyError(f"{where}.path: must stay within the pinned repository")
    return RepoPin(repo=repo, sha=sha, path=path)


def load_cohort(path: Path) -> list[StudyCase]:
    document = _load_yaml(path)
    if document.get("schema_version") != SCHEMA_VERSION:
        raise StudyError(f"{path}: schema_version must be {SCHEMA_VERSION}")
    if document.get("study") != "deployment-authority-v08":
        raise StudyError(f"{path}: study must be deployment-authority-v08")
    cases = document.get("cases")
    if not isinstance(cases, list):
        raise StudyError(f"{path}: cases must be a list")

    root = path.parent
    result: list[StudyCase] = []
    seen: set[str] = set()
    for index, raw in enumerate(cases):
        where = f"cases[{index}]"
        if not isinstance(raw, dict):
            raise StudyError(f"{where}: expected a mapping")
        case_id = _require_string(raw, "case_id", where)
        if case_id in seen:
            raise StudyError(f"{where}.case_id: duplicate {case_id}")
        seen.add(case_id)
        kind = _require_string(raw, "kind", where)
        if kind not in CASE_KINDS:
            raise StudyError(f"{where}.kind: expected one of {sorted(CASE_KINDS)}")
        provider = _require_string(raw, "provider", where)
        if provider != "gcp":
            raise StudyError(f"{where}.provider: v0.8 study is intentionally GCP-only")
        framework = _require_string(raw, "framework", where)
        application = _repo_pin(raw.get("application"), f"{where}.application")
        infrastructure_raw = raw.get("infrastructure")
        infrastructure = (
            _repo_pin(infrastructure_raw, f"{where}.infrastructure")
            if infrastructure_raw is not None
            else None
        )
        if kind in {"natural", "mutation"} and infrastructure is None:
            raise StudyError(f"{where}.infrastructure: required for {kind} cases")

        evidence_value = _require_string(raw, "deployment_evidence", where)
        truth_value = _require_string(raw, "ground_truth", where)
        deployment_evidence = _safe_study_path(
            root, evidence_value, f"{where}.deployment_evidence"
        )
        ground_truth = _safe_study_path(root, truth_value, f"{where}.ground_truth")
        result.append(
            StudyCase(
                case_id=case_id,
                kind=kind,
                provider=provider,
                framework=framework,
                application=application,
                infrastructure=infrastructure,
                deployment_evidence=deployment_evidence,
                ground_truth=ground_truth,
            )
        )
    return result


def _safe_study_path(root: Path, value: str, where: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise StudyError(f"{where}: must stay within the study directory")
    resolved = root / relative
    if not resolved.is_file():
        raise StudyError(f"{where}: file does not exist: {relative}")
    return resolved


def validate_ground_truth(path: Path, case_id: str) -> dict[str, Any]:
    document = _load_yaml(path)
    if document.get("schema_version") != SCHEMA_VERSION:
        raise StudyError(f"{path}: schema_version must be {SCHEMA_VERSION}")
    if document.get("case_id") != case_id:
        raise StudyError(f"{path}: case_id must match {case_id}")
    if document.get("reviewed") is not True:
        raise StudyError(f"{path}: reviewed must be true before a case can run")

    expected = document.get("expected")
    if not isinstance(expected, dict):
        raise StudyError(f"{path}: expected must be a mapping")
    if expected.get("runtime_effectiveness") != "not_verified":
        raise StudyError(f"{path}: runtime_effectiveness must be not_verified")
    agents = expected.get("agents")
    if not isinstance(agents, list) or not agents:
        raise StudyError(f"{path}: expected.agents must be a non-empty list")

    seen_agents: set[str] = set()
    for index, item in enumerate(agents):
        where = f"{path}: expected.agents[{index}]"
        if not isinstance(item, dict):
            raise StudyError(f"{where}: expected a mapping")
        agent = _require_string(item, "agent", where)
        if agent in seen_agents:
            raise StudyError(f"{where}.agent: duplicate {agent}")
        seen_agents.add(agent)
        _require_string(item, "identity", where)
        status = _require_string(item, "status", where)
        if status not in STATUSES:
            raise StudyError(f"{where}.status: expected one of {list(STATUSES)}")
        for section in ("required", "deployed", "excess", "missing"):
            section_value = item.get(section)
            if not isinstance(section_value, dict):
                raise StudyError(f"{where}.{section}: expected a mapping")
            for dimension in ("roles", "permissions"):
                _string_list(
                    section_value.get(dimension),
                    f"{where}.{section}.{dimension}",
                )
        _string_list(item.get("conditional_roles"), f"{where}.conditional_roles")
        _string_list(item.get("conditional_permissions"), f"{where}.conditional_permissions")
        _string_list(item.get("unresolved"), f"{where}.unresolved")

    evidence = document.get("evidence")
    if not isinstance(evidence, dict):
        raise StudyError(f"{path}: evidence must be a mapping")
    for category in ("application", "infrastructure"):
        entries = evidence.get(category)
        if not isinstance(entries, list) or not entries:
            raise StudyError(f"{path}: evidence.{category} must be a non-empty list")
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise StudyError(f"{path}: evidence.{category}[{index}] must be a mapping")
            _require_string(entry, "path", f"{path}: evidence.{category}[{index}]")
            _require_string(
                entry,
                "rationale",
                f"{path}: evidence.{category}[{index}]",
            )
    return document


def _string_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise StudyError(f"{where}: expected a list of non-empty strings")
    if len(value) != len(set(value)):
        raise StudyError(f"{where}: duplicate values are not allowed")
    return value


def validate_case_inputs(case: StudyCase) -> dict[str, Any]:
    evidence = _load_yaml(case.deployment_evidence)
    if evidence.get("schema_version") != 1:
        raise StudyError(
            f"{case.deployment_evidence}: expected Deployment Evidence schema_version 1"
        )
    if evidence.get("provider") != case.provider:
        raise StudyError(f"{case.deployment_evidence}: provider must match case provider")
    return validate_ground_truth(case.ground_truth, case.case_id)


def _run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        command,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def fetch_pinned_repo(root: Path, pin: RepoPin, label: str) -> Path:
    target = root / label
    target.mkdir(parents=True, exist_ok=True)
    commands = [
        ["git", "init", "-q", str(target)],
        [
            "git",
            "-C",
            str(target),
            "remote",
            "add",
            "origin",
            f"https://github.com/{pin.repo}.git",
        ],
        [
            "git",
            "-C",
            str(target),
            "fetch",
            "--quiet",
            "--depth=1",
            "--filter=blob:none",
            "origin",
            pin.sha,
        ],
        ["git", "-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
    ]
    for command in commands:
        result = _run(command, timeout=CLONE_TIMEOUT)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[-3000:]
            raise StudyError(f"{pin.repo}@{pin.sha}: fetch failed: {detail}")
    revision = _run(["git", "-C", str(target), "rev-parse", "HEAD"], timeout=30)
    resolved = revision.stdout.strip() if revision.returncode == 0 else ""
    if resolved != pin.sha:
        raise StudyError(
            f"{pin.repo}: frozen SHA mismatch: expected {pin.sha}, got {resolved}"
        )
    selected = target / pin.path
    if not selected.exists():
        raise StudyError(
            f"{pin.repo}@{pin.sha}: selected path does not exist: {pin.path}"
        )
    return selected


def build_reconcile_command(
    application: Path,
    evidence: Path,
    infrastructure: Path | None,
) -> list[str]:
    command = [
        "horustrace",
        "reconcile",
        str(application),
        "--deployment-evidence",
        str(evidence),
        "--format",
        "json",
    ]
    if infrastructure is not None:
        command.extend(["--authority-source", str(infrastructure)])
    return command


def evaluate_report(report: dict[str, Any], truth: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    if report.get("runtime_effectiveness") != "not_verified":
        failures.append("runtime_effectiveness must remain not_verified")

    observed_agents = {
        item.get("agent"): item
        for item in report.get("reconciliation", {}).get("agents", [])
        if isinstance(item, dict) and isinstance(item.get("agent"), str)
    }
    identity_by_agent: dict[str, set[str]] = {}
    for relationship in report.get("deployed_identity", {}).get("relationships", []):
        if not isinstance(relationship, dict):
            continue
        agent = relationship.get("agent")
        identity = relationship.get("identity")
        if isinstance(agent, str) and isinstance(identity, str):
            identity_by_agent.setdefault(agent, set()).add(identity)

    comparisons: list[dict[str, Any]] = []
    for expected in truth["expected"]["agents"]:
        agent = expected["agent"]
        observed = observed_agents.get(agent)
        agent_failures: list[str] = []
        if observed is None:
            agent_failures.append("agent missing from reconciliation report")
            observed_status = "missing_report_agent"
        else:
            observed_status = str(observed.get("status"))
            _compare_scalar(
                agent_failures,
                "status",
                expected["status"],
                observed.get("status"),
            )
            _compare_scalar(
                agent_failures,
                "identity",
                expected["identity"],
                (
                    expected["identity"]
                    if expected["identity"] in identity_by_agent.get(agent, set())
                    else None
                ),
            )
            for section in ("required", "deployed", "excess", "missing"):
                observed_section = (
                    observed.get(section)
                    if isinstance(observed.get(section), dict)
                    else {}
                )
                for dimension in ("roles", "permissions"):
                    _compare_list(
                        agent_failures,
                        f"{section}.{dimension}",
                        expected[section][dimension],
                        observed_section.get(dimension),
                    )
            deployed_section = (
                observed.get("deployed")
                if isinstance(observed.get("deployed"), dict)
                else {}
            )
            _compare_list(
                agent_failures,
                "conditional_roles",
                expected["conditional_roles"],
                deployed_section.get("conditional_roles"),
            )
            _compare_list(
                agent_failures,
                "conditional_permissions",
                expected["conditional_permissions"],
                deployed_section.get("conditional_permissions"),
            )
            _compare_list(
                agent_failures,
                "unresolved",
                expected["unresolved"],
                observed.get("unresolved"),
            )

        failures.extend(f"{agent}: {item}" for item in agent_failures)
        comparisons.append(
            {
                "agent": agent,
                "expected_status": expected["status"],
                "observed_status": observed_status,
                "passed": not agent_failures,
                "failures": agent_failures,
            }
        )

    return {"passed": not failures, "failures": failures, "agents": comparisons}


def _compare_scalar(
    failures: list[str],
    field: str,
    expected: Any,
    observed: Any,
) -> None:
    if expected != observed:
        failures.append(f"{field}: expected {expected!r}, observed {observed!r}")


def _compare_list(
    failures: list[str],
    field: str,
    expected: list[str],
    observed: Any,
) -> None:
    observed_list = observed if isinstance(observed, list) else []
    if sorted(expected) != sorted(str(item) for item in observed_list):
        failures.append(
            f"{field}: expected {sorted(expected)!r}, observed {sorted(observed_list)!r}"
        )


def run_case(
    case: StudyCase,
    truth: dict[str, Any],
    workspace: Path,
) -> dict[str, Any]:
    case_root = workspace / case.case_id
    application = fetch_pinned_repo(case_root, case.application, "application")
    infrastructure = (
        fetch_pinned_repo(case_root, case.infrastructure, "infrastructure")
        if case.infrastructure is not None
        else None
    )
    command = build_reconcile_command(
        application,
        case.deployment_evidence.resolve(),
        infrastructure,
    )
    result = _run(command, timeout=ANALYSIS_TIMEOUT)
    if result.returncode not in {0, 2}:
        detail = (result.stderr or result.stdout).strip()[-5000:]
        raise StudyError(
            f"{case.case_id}: reconcile failed with exit {result.returncode}: {detail}"
        )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise StudyError(f"{case.case_id}: reconcile did not emit valid JSON") from exc
    evaluation = evaluate_report(report, truth)
    return {
        "case_id": case.case_id,
        "kind": case.kind,
        "provider": case.provider,
        "framework": case.framework,
        "application": {
            "repo": case.application.repo,
            "sha": case.application.sha,
            "path": case.application.path,
        },
        "infrastructure": (
            {
                "repo": case.infrastructure.repo,
                "sha": case.infrastructure.sha,
                "path": case.infrastructure.path,
            }
            if case.infrastructure is not None
            else None
        ),
        "passed": evaluation["passed"],
        "evaluation": evaluation,
        "report": report,
    }


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    confusion = {
        expected: {observed: 0 for observed in STATUSES}
        for expected in STATUSES
    }
    unclassified = 0
    agents = 0
    for result in results:
        for comparison in result.get("evaluation", {}).get("agents", []):
            agents += 1
            expected = comparison.get("expected_status")
            observed = comparison.get("observed_status")
            if expected in confusion and observed in confusion[expected]:
                confusion[expected][observed] += 1
            else:
                unclassified += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "study": "deployment-authority-v08",
        "summary": {
            "cases": len(results),
            "passed": sum(bool(item.get("passed")) for item in results),
            "failed": sum(not bool(item.get("passed")) for item in results),
            "agents_adjudicated": agents,
            "unclassified_agent_results": unclassified,
        },
        "classification_confusion_matrix": confusion,
        "cases": results,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# HorusTrace v0.8 deployment-authority study",
        "",
        "Targets are pinned to exact Git commit SHAs. Target applications are not "
        "installed, imported, or executed.",
        "Terraform is repository-declared authority evidence; runtime effectiveness "
        "remains not_verified.",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Cases | {summary['cases']} |",
        f"| Passed | {summary['passed']} |",
        f"| Failed | {summary['failed']} |",
        f"| Agents adjudicated | {summary['agents_adjudicated']} |",
        f"| Unclassified agent results | {summary['unclassified_agent_results']} |",
        "",
        "## Cases",
        "",
        "| Case | Kind | Framework | Result |",
        "| --- | --- | --- | --- |",
    ]
    for item in report["cases"]:
        lines.append(
            f"| {item['case_id']} | {item['kind']} | {item['framework']} | "
            f"{'PASS' if item['passed'] else 'FAIL'} |"
        )
    lines.extend(["", "## Classification confusion matrix", ""])
    matrix = report["classification_confusion_matrix"]
    header = "| Expected \\ Observed | " + " | ".join(STATUSES) + " |"
    lines.extend(
        [
            header,
            "| --- | " + " | ".join("---:" for _ in STATUSES) + " |",
        ]
    )
    for expected in STATUSES:
        lines.append(
            f"| {expected} | "
            + " | ".join(
                str(matrix[expected][observed]) for observed in STATUSES
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cohort",
        type=Path,
        default=Path("research/deployment-authority-v08/cohort.yaml"),
    )
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-markdown", type=Path)
    parser.add_argument("--keep-workspace", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        cases = load_cohort(args.cohort)
        truths = {
            case.case_id: validate_case_inputs(case)
            for case in cases
        }
        if args.validate_only:
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "cases": len(cases),
                        "valid": True,
                    },
                    indent=2,
                )
            )
            return 0

        if args.keep_workspace is not None:
            args.keep_workspace.mkdir(parents=True, exist_ok=True)
            workspace = args.keep_workspace
            cleanup = False
        else:
            workspace = Path(
                tempfile.mkdtemp(prefix="horustrace-deployment-study-")
            )
            cleanup = True
        try:
            results = [
                run_case(case, truths[case.case_id], workspace)
                for case in cases
            ]
        finally:
            if cleanup:
                shutil.rmtree(workspace, ignore_errors=True)
        report = aggregate(results)
        payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(payload, encoding="utf-8")
        else:
            print(payload, end="")
        if args.output_markdown:
            args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
            args.output_markdown.write_text(
                render_markdown(report),
                encoding="utf-8",
            )
        return 0 if report["summary"]["failed"] == 0 else 1
    except (StudyError, subprocess.TimeoutExpired) as exc:
        print(f"study error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
