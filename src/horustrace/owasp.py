from __future__ import annotations

from collections import Counter

from horustrace.models import Finding, Severity
from horustrace.rule_registry import OWASP_AGENTIC_TAXONOMY, iter_rule_metadata


def build_owasp_agentic_summary(
    findings: list[Finding],
    disabled_rules: list[str] | set[str] | tuple[str, ...] = (),
) -> dict:
    """Build a conservative OWASP Agentic Top 10 coverage summary.

    A category is "not_assessed" when HorusTrace has no mapped detector for it.
    "no_mapped_findings" means mapped detectors exist but none fired in this scan;
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
        if category_findings:
            status = "finding"
            highest = max(f.severity for f in category_findings).label()
        elif rules:
            status = "no_mapped_findings"
            highest = None
        else:
            status = "not_assessed"
            highest = None

        categories.append(
            {
                "id": risk_id,
                "title": title,
                "status": status,
                "mapped_rules": rules,
                "disabled_mapped_rules": disabled_mapped_rules,
                "available_mapped_rules": all_rules,
                "finding_count": len(category_findings),
                "highest_severity": highest,
                "finding_rule_ids": sorted({f.rule_id for f in category_findings}),
            }
        )

    status_counts = Counter(item["status"] for item in categories)
    return {
        "standard": "OWASP Top 10 for Agentic Applications 2026",
        "semantics": {
            "finding": "One or more mapped HorusTrace rules fired.",
            "no_mapped_findings": (
                "HorusTrace has one or more mapped detectors, but none fired in this scan. "
                "This is not a claim of complete OWASP coverage or runtime safety."
            ),
            "not_assessed": "HorusTrace currently has no mapped detector for this category.",
        },
        "summary": {
            "categories": len(categories),
            "categories_with_mapped_detectors": sum(bool(item["mapped_rules"]) for item in categories),
            "categories_with_findings": status_counts["finding"],
            "categories_not_assessed": status_counts["not_assessed"],
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
            "Status semantics: FINDING = mapped rule fired; "
            "NO MAPPED FINDINGS = mapped detector exists but did not fire; "
            "NOT ASSESSED = no mapped detector."
        ),
        "",
    ]

    for item in report["categories"]:
        if item["status"] == "finding":
            detail = (
                f"FINDING ({item['finding_count']}; highest={item['highest_severity']})"
            )
        elif item["status"] == "no_mapped_findings":
            detail = "NO MAPPED FINDINGS"
        else:
            detail = "NOT ASSESSED"
        lines.append(f"{item['id']}  {item['title']}: {detail}")
        if item["mapped_rules"]:
            lines.append("  Enabled mapped rules: " + ", ".join(item["mapped_rules"]))
        if item["disabled_mapped_rules"]:
            lines.append(
                "  Disabled mapped rules: " + ", ".join(item["disabled_mapped_rules"])
            )
        if item["finding_rule_ids"]:
            lines.append("  Triggered rules: " + ", ".join(item["finding_rule_ids"]))

    lines.extend(
        [
            "",
            (
                "Mapped coverage is detector-level coverage, not proof that an OWASP "
                "category is fully mitigated or absent at runtime."
            ),
        ]
    )
    return "\n".join(lines)
