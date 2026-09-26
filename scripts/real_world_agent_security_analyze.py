"""Derive error taxonomy and product-development priorities from the frozen baseline."""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

CATEGORY_TO_PRODUCT = {
    "execution_failure": {
        "title": "Scanner robustness on real repositories",
        "area": "scanner-core",
        "acceptance": "Frozen cohort execution failure rate <= 1% without target execution.",
    },
    "framework_root_discovery": {
        "title": "Framework/workflow root discovery",
        "area": "framework-adapters",
        "acceptance": "Agent/workflow entity recall >= 0.90 on the identical frozen cohort.",
    },
    "agent_entity_false_positive": {
        "title": "Agent entity precision",
        "area": "framework-adapters",
        "acceptance": "Agent/workflow entity precision >= 0.95 on completeness-marked cases.",
    },
    "tool_discovery": {
        "title": "Tool binding discovery",
        "area": "framework-adapters",
        "acceptance": "Tool edge recall >= 0.85 on the identical frozen cohort.",
    },
    "tool_false_positive": {
        "title": "Tool binding precision",
        "area": "framework-adapters",
        "acceptance": "Tool edge precision >= 0.90 on completeness-marked cases.",
    },
    "mcp_discovery": {
        "title": "MCP server and binding discovery",
        "area": "mcp-resolution",
        "acceptance": "MCP discovery/binding recall >= 0.85 on source-adjudicated references.",
    },
    "mcp_false_positive": {
        "title": "MCP binding precision",
        "area": "mcp-resolution",
        "acceptance": "MCP precision >= 0.90 on completeness-marked cases.",
    },
    "delegation_resolution": {
        "title": "Delegation and handoff topology",
        "area": "authority-graph",
        "acceptance": "Delegation edge recall >= 0.85 on the identical frozen cohort.",
    },
    "delegation_false_positive": {
        "title": "Delegation topology precision",
        "area": "authority-graph",
        "acceptance": "Delegation edge precision >= 0.90 on completeness-marked cases.",
    },
    "effective_authority_recall": {
        "title": "Effective agent-to-tool/MCP authority reconstruction",
        "area": "authority-resolution",
        "acceptance": "Effective-authority recall >= 0.80 on Tier B without lowering precision below 0.90.",
    },
    "effective_authority_false_positive": {
        "title": "Effective-authority precision",
        "area": "authority-resolution",
        "acceptance": "Effective-authority precision >= 0.90 on completeness-marked Tier B cases.",
    },
    "attack_path_structural_support": {
        "title": "Attack-path reachability/source-sink validation",
        "area": "attack-paths",
        "acceptance": "Source-adjudicable attack-path structural support precision >= 0.80.",
    },
    "deployment_identity": {
        "title": "Cross-provider deployment identity/IAM reconstruction",
        "area": "deployment-authority",
        "acceptance": "Repository-declared identity recall >= 0.90 on the frozen Tier C cases and provider coverage gaps remain explicit.",
    },
    "analysis_incomplete": {
        "title": "Conservative dynamic/unsupported evidence handling",
        "area": "coverage-diagnostics",
        "acceptance": "Reduce incomplete analysis while preserving unresolved rather than unsupported certainty.",
    },
}


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected object")
    return value


def issue(
    counts: Counter[str],
    frameworks: dict[str, Counter[str]],
    category: str,
    framework: str,
) -> None:
    counts[category] += 1
    frameworks[category][framework] += 1


def derive(report: dict[str, Any]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    frameworks: dict[str, Counter[str]] = defaultdict(Counter)
    examples: dict[str, list[dict[str, str]]] = defaultdict(list)

    for case in report.get("cases") or []:
        framework = str(case.get("framework") or "unknown")
        status = case.get("status")
        if status != "success":
            issue(counts, frameworks, "execution_failure", framework)
            if len(examples["execution_failure"]) < 8:
                examples["execution_failure"].append({
                    "case_id": str(case.get("case_id")),
                    "repo": str(case.get("repo")),
                    "detail": str(case.get("error") or status),
                })
            continue

        observed = case.get("observed") or {}
        if observed.get("analysis_incomplete"):
            issue(counts, frameworks, "analysis_incomplete", framework)

        comparisons = case.get("comparisons") or {}
        for key, miss_category, fp_category in (
            ("agent_entities", "framework_root_discovery", "agent_entity_false_positive"),
            ("tools", "tool_discovery", "tool_false_positive"),
            ("mcp_servers", "mcp_discovery", "mcp_false_positive"),
            ("delegation_edges", "delegation_resolution", "delegation_false_positive"),
            ("effective_authority", "effective_authority_recall", "effective_authority_false_positive"),
        ):
            item = comparisons.get(key)
            if not isinstance(item, dict):
                continue
            if int(item.get("fn", 0)) > 0:
                issue(counts, frameworks, miss_category, framework)
                if len(examples[miss_category]) < 8:
                    examples[miss_category].append({
                        "case_id": str(case.get("case_id")),
                        "repo": str(case.get("repo")),
                        "detail": f"{key}: {item.get('fn')} missed of {item.get('truth')} source references",
                    })
            if item.get("precision_eligible") and int(item.get("fp", 0)) > 0:
                issue(counts, frameworks, fp_category, framework)
                if len(examples[fp_category]) < 8:
                    examples[fp_category].append({
                        "case_id": str(case.get("case_id")),
                        "repo": str(case.get("repo")),
                        "detail": f"{key}: {item.get('fp')} unmatched predictions on a completeness-marked reference",
                    })

        attack = comparisons.get("attack_paths")
        if isinstance(attack, dict) and int(attack.get("unsupported_within_reference", 0)) > 0:
            issue(counts, frameworks, "attack_path_structural_support", framework)
            if len(examples["attack_path_structural_support"]) < 8:
                examples["attack_path_structural_support"].append({
                    "case_id": str(case.get("case_id")),
                    "repo": str(case.get("repo")),
                    "detail": f"{attack.get('unsupported_within_reference')} source-adjudicable reported paths lacked a matching explicit authority pair",
                })

        identity = comparisons.get("tier_c_identity")
        if isinstance(identity, dict) and int(identity.get("fn", 0)) > 0:
            issue(counts, frameworks, "deployment_identity", framework)
            if len(examples["deployment_identity"]) < 8:
                examples["deployment_identity"].append({
                    "case_id": str(case.get("case_id")),
                    "repo": str(case.get("repo")),
                    "detail": f"{identity.get('fn')} repository-declared identities were not recovered",
                })

    total_cases = int(report.get("cohort_cases") or len(report.get("cases") or []))
    priorities: list[dict[str, Any]] = []
    for category, affected in counts.items():
        product = CATEGORY_TO_PRODUCT.get(category)
        if product is None:
            continue
        framework_counts = dict(frameworks[category].most_common())
        breadth = len(framework_counts)
        security_weight = 3 if category in {
            "effective_authority_recall",
            "effective_authority_false_positive",
            "attack_path_structural_support",
            "deployment_identity",
        } else 2 if category in {
            "framework_root_discovery", "tool_discovery", "mcp_discovery",
            "delegation_resolution", "execution_failure",
        } else 1
        score = affected * security_weight + breadth * 2
        priorities.append({
            "category": category,
            "title": product["title"],
            "area": product["area"],
            "affected_cases": affected,
            "affected_fraction": round(affected / total_cases, 4) if total_cases else None,
            "frameworks": framework_counts,
            "security_weight": security_weight,
            "priority_score": score,
            "acceptance_criterion": product["acceptance"],
            "examples": examples.get(category, []),
        })
    priorities.sort(key=lambda x: (-x["priority_score"], -x["affected_cases"], x["category"]))
    for index, item in enumerate(priorities, start=1):
        item["rank"] = index
        item["priority"] = "P0" if index <= 3 else "P1" if index <= 7 else "P2"

    limitations = [
        {
            "category": "finding_semantics_validation_gap",
            "product_implication": "Create a human-adjudicated finding assertion corpus before using finding counts as product-accuracy claims.",
            "reason": report.get("findings", {}).get("reason"),
        },
        {
            "category": "attack_path_recall_validation_gap",
            "product_implication": "Pre-adjudicate known valid/invalid Tier-B paths to measure attack-path recall, not only structural support precision.",
            "reason": report.get("attack_paths", {}).get("known_path_recall_reason"),
        },
        {
            "category": "human_dual_review_gap",
            "product_implication": "Before external/public accuracy claims, independently human-review the 60 Tier-B and four Tier-C references.",
            "reason": "Current reference is an automated independent dual-pass source review, transparently not a human panel.",
        },
        {
            "category": "tier_c_public_evidence_scarcity",
            "product_implication": "Keep deployment/IAM as an overlapping evidence tier; do not distort the broad application cohort to manufacture IaC coverage.",
            "reason": f"Only {report.get('tier_c', {}).get('selected_cases')} defensible Tier-C cases survived the independently selected broad cohort versus target 25.",
        },
    ]
    return {
        "schema_version": 1,
        "study": report.get("study"),
        "scanner_sha": report.get("scanner_sha"),
        "cohort_cases": total_cases,
        "error_taxonomy": {
            "affected_case_counts": dict(counts.most_common()),
            "framework_breakdown": {
                category: dict(counter.most_common())
                for category, counter in sorted(frameworks.items())
            },
        },
        "product_priorities": priorities,
        "validation_limitations": limitations,
    }


def render(value: dict[str, Any]) -> str:
    lines = [
        "# Real-World Study — Error Analysis and Product Roadmap",
        "",
        f"Frozen scanner: \`{value['scanner_sha']}\`",
        f"Cohort: {value['cohort_cases']} repositories",
        "",
        "## Measured error taxonomy",
        "",
        "| Category | Affected cases |",
        "| --- | ---: |",
    ]
    for category, count in value["error_taxonomy"]["affected_case_counts"].items():
        lines.append(f"| {category} | {count} |")

    lines.extend([
        "",
        "## Product priorities",
        "",
        "| Rank | Priority | Product area | Evidence | Acceptance criterion |",
        "| ---: | --- | --- | ---: | --- |",
    ])
    for item in value["product_priorities"]:
        lines.append(
            f"| {item['rank']} | {item['priority']} | {item['title']} | "
            f"{item['affected_cases']} cases | {item['acceptance_criterion']} |"
        )
    lines.extend([
        "",
        "### Framework concentration",
        "",
    ])
    for item in value["product_priorities"][:7]:
        lines.append(
            f"- **{item['title']}** — "
            + ", ".join(f"{name}: {count}" for name, count in item["frameworks"].items())
        )

    lines.extend([
        "",
        "## Validation work that remains separate from scanner fixes",
        "",
    ])
    for item in value["validation_limitations"]:
        lines.append(f"- **{item['category']}** — {item['product_implication']}")

    lines.extend([
        "",
        "## Development rule",
        "",
        "Implement product changes only after this frozen baseline is immutable. Every accepted change should be rerun against the identical 180-repository cohort, preserving the original baseline and reporting post-fix deltas by framework.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-markdown", type=Path, required=True)
    args = parser.parse_args()
    value = derive(load(args.baseline))
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_markdown.write_text(render(value) + "\n", encoding="utf-8")
    print(json.dumps(value["error_taxonomy"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
