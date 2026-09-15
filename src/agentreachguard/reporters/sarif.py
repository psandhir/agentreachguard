from __future__ import annotations

from agentreachguard.models import Finding

LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render(findings: list[Finding]) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.recommendation},
            },
        )
        result = {
            "ruleId": finding.rule_id,
            "level": LEVELS[finding.severity.label()],
            "message": {"text": finding.message},
            "properties": {
                "agentreachguardLayer": finding.layer,
                "agent": finding.agent,
                "evidence": finding.evidence,
                "standards": finding.standards,
            },
        }
        if finding.location:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(finding.location.path)},
                        "region": {
                            "startLine": max(1, finding.location.line),
                            "startColumn": max(1, finding.location.column),
                        },
                    }
                }
            ]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentReachGuard",
                        "informationUri": "https://github.com/psandhir/agentreachguard",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
