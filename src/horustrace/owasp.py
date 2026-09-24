from __future__ import annotations

from collections import Counter

from horustrace.models import Finding
from horustrace.rule_registry import OWASP_AGENTIC_TAXONOMY, iter_rule_metadata
from horustrace.source_context import NON_RUNTIME_SOURCE_CONTEXTS, SOURCE_CONTEXTS


def _source_context_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter((finding.source_context or "unknown") for finding in findings)
    return {context: counts.get(context, 0) for context in SOURCE_CONTEXTS}


def build_owasp_agentic_summary(
    findings: list[Finding],
    disabled_rules: list[str] | set[str] | tuple[str, ...] = (),
) -> dict:
    """Build a conservative OWASP Agentic Top 10 coverage summary.

    The existing detector-centric status field is preserved for backwards compatibility.
    runtime_status separates runtime-classified findings from findings in tests, examples,
    tutorials, notebooks, CLI/support code, templates, or unknown context.

    A category is not_assessed when HorusTrace has no enabled mapped detector for it.
    no_mapped_findings means mapped detectors exist but none fired in this scan;
    it does not mean the category is comprehensively covered or absent at runtime.
    """
    mapped_rules: dict[str, list[str]] = {
        risk_id: [] for risk_id in OWASP_AGENTIC_TAXONOMY
    }
    for rule in iter_rule_metadata():
        for risk_id in rule.owasp_agentic:
            mapped_rules[risk_id].append(rule.rule_id)

    disabled = set(disabled_rules)
    findings_by_risk: dict[str, list[Finding]] = {
        risk_id: [] for risk_id in OWASP_AGENTIC_TAXONOMY
    }
    for finding in findings:
        for risk_id in finding.standards.get("owasp_agentic", []):
            if risk_id in findings_by_risk:
                findings_by_risk[risk_id].append(finding)

    categories = []
    for risk_id, title in OWASP_AGENTIC_TAXONOMY.items():
        category_findings = findings_by_risk[risk_id]
        all_rules = sorted(mapped_rules[risk_id])
        rules = [rule_id for rule_id in all_rules if rule_id not in disabled]
        disabled_mapped_rules = [
            rule_id for rule_id in all_rules if rule_id in disabled
        ]
        source_contexts = _source_context_counts(category_findings)
        runtime_findings = [
            finding
            for finding in category_findings
            if (finding.source_context or "unknown") == "runtime"
        ]
        non_runtime_findings = [
            finding
            for finding in category_findings
            if (finding.source_context or "unknown") in NON_RUNTIME_SOURCE_CONTEXTS
        ]
        unknown_context_findings = [
            finding
            for finding in category_findings
            if (finding.source_context or "unknown") == "unknown"
        ]

        if category_findings:
            status = "finding"
            highest = max(f.severity for f in category_findings).label()
        elif rules:
            status = "no_mapped_findings"
            highest = None
        else:
            status = "not_assessed"
            highest = None

        if not rules:
            runtime_status = "not_assessed"
        elif runtime_findings:
            runtime_status = "finding"
        elif category_findings:
            runtime_status = "no_runtime_findings"
        else:
            runtime_status = "no_mapped_findings"

        categories.append(
            {
                "id": risk_id,
                "title": title,
                "status": status,
                "runtime_status": runtime_status,
                "mapped_rules": rules,
                "disabled_mapped_rules": disabled_mapped_rules,
                "available_mapped_rules": all_rules,
                "finding_count": len(category_findings),
                "runtime_finding_count": len(runtime_findings),
                "non_runtime_finding_count": len(non_runtime_findings),
                "unknown_source_context_finding_count": len(unknown_context_findings),
                "source_contexts": source_contexts,
                "highest_severity": highest,
                "finding_rule_ids": sorted({f.rule_id for f in category_findings}),
                "runtime_finding_rule_ids": sorted(
                    {f.rule_id for f in runtime_findings}
                ),
                "affected_agents": sorted(
                    {f.agent for f in category_findings if f.agent}
                ),
                "runtime_affected_agents": sorted(
                    {f.agent for f in runtime_findings if f.agent}
                ),
            }
        )

    status_counts = Counter(item["status"] for item in categories)
    runtime_status_counts = Counter(item["runtime_status"] for item in categories)
    mapped_finding_ids = {
        id(finding)
        for finding in findings
        if finding.standards.get("owasp_agentic")
    }
    runtime_mapped_finding_ids = {
        id(finding)
        for finding in findings
        if finding.standards.get("owasp_agentic")
        and (finding.source_context or "unknown") == "runtime"
    }
    return {
        "standard": "OWASP Top 10 for Agentic Applications 2026",
        "semantics": {
            "finding": "One or more mapped HorusTrace rules fired.",
            "no_mapped_findings": (
                "HorusTrace has one or more mapped detectors, but none fired in this scan. "
                "This is not a claim of complete OWASP coverage or runtime safety."
            ),
            "not_assessed": (
                "HorusTrace currently has no enabled mapped detector for this category."
            ),
            "runtime_finding": (
                "One or more mapped findings are classified as runtime application source."
            ),
            "no_runtime_findings": (
                "Mapped findings fired, but none are classified as runtime application source. "
                "Unknown source context is reported separately and is not treated as non-runtime."
            ),
        },
        "summary": {
            "categories": len(categories),
            "categories_with_mapped_detectors": sum(
                bool(item["mapped_rules"]) for item in categories
            ),
            "categories_with_findings": status_counts["finding"],
            "categories_with_runtime_findings": runtime_status_counts["finding"],
            "categories_with_only_non_runtime_or_unknown_findings": (
                runtime_status_counts["no_runtime_findings"]
            ),
            "categories_not_assessed": status_counts["not_assessed"],
            "mapped_findings": len(mapped_finding_ids),
            "runtime_mapped_findings": len(runtime_mapped_finding_ids),
        },
        "categories": categories,
    }


def render_owasp_agentic_console(
    findings: list[Finding],
    disabled_rules: list[str] | set[str] | tuple[str, ...] = (),
) -> str:
    report = build_owasp_agentic_summary(findings, disabled_rules=disabled_rules)
    lines = [
        "OWASP Agentic Top 10 Coverage",
        "=" * 29,
        (
            "Runtime-first view: FINDING = runtime-classified mapped finding; "
            "NO RUNTIME FINDINGS = mapped findings exist only outside runtime or in unknown "
            "context; NO MAPPED FINDINGS = enabled mapped detector exists but did not fire; "
            "NOT ASSESSED = no enabled mapped detector."
        ),
        "",
    ]

    for item in report["categories"]:
        if item["runtime_status"] == "finding":
            detail = (
                f"FINDING (runtime={item['runtime_finding_count']} / "
                f"total={item['finding_count']}; highest={item['highest_severity']})"
            )
        elif item["runtime_status"] == "no_runtime_findings":
            detail = (
                f"NO RUNTIME FINDINGS (total={item['finding_count']}; "
                f"highest={item['highest_severity']})"
            )
        elif item["runtime_status"] == "no_mapped_findings":
            detail = "NO MAPPED FINDINGS"
        else:
            detail = "NOT ASSESSED"
        lines.append(f"{item['id']}  {item['title']}: {detail}")

        nonzero_contexts = [
            f"{context}={count}"
            for context, count in item["source_contexts"].items()
            if count
        ]
        if nonzero_contexts:
            lines.append("  Source contexts: " + ", ".join(nonzero_contexts))
        if item["mapped_rules"]:
            lines.append("  Enabled mapped rules: " + ", ".join(item["mapped_rules"]))
        if item["disabled_mapped_rules"]:
            lines.append(
                "  Disabled mapped rules: " + ", ".join(item["disabled_mapped_rules"])
            )
        if item["finding_rule_ids"]:
            lines.append("  Triggered rules: " + ", ".join(item["finding_rule_ids"]))
        if item["runtime_finding_rule_ids"]:
            lines.append(
                "  Runtime triggered rules: "
                + ", ".join(item["runtime_finding_rule_ids"])
            )

    lines.extend(
        [
            "",
            (
                "Source-context classification helps distinguish runtime application evidence "
                "from tests, examples, tutorials, notebooks, CLI/support code and templates. "
                "Mapped coverage is still detector-level coverage, not proof that an OWASP "
                "category is fully mitigated or absent at runtime."
            ),
        ]
    )
    return "\n".join(lines)
