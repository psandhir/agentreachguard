from __future__ import annotations

from agentreachguard.models import Finding, ScanCoverage
from agentreachguard.rule_registry import get_rule_metadata

LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render(findings: list[Finding], coverage: ScanCoverage | None = None,
           controls: list[dict] | None = None,
           suppressed: list[Finding] | None = None,
           suppression_diagnostics: list[dict] | None = None) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.recommendation},
                "properties": {"standards": finding.standards},
            },
        )
        try:
            default_severity = get_rule_metadata(finding.rule_id).default_severity.label()
        except KeyError:
            # Synthetic findings used by integrations may not be in the built-in catalogue.
            default_severity = finding.severity.label()
        result = {
            "ruleId": finding.rule_id,
            "level": LEVELS[finding.severity.label()],
            "message": {"text": finding.message},
            "properties": {
                "agentreachguardLayer": finding.layer,
                "default_severity": default_severity,
                "effective_severity": finding.severity.label(),
                "agent": finding.agent,
                "evidence": finding.evidence,
                "standards": finding.standards,
                "assessment": finding.assessment,
                "provenance": [fact.as_dict() for fact in finding.provenance],
                "limitations": finding.limitations,
                "fingerprint": finding.fingerprint,
                "confidence": finding.confidence.value if finding.confidence else None,
            },
        }
        if finding.fingerprint:
            result["partialFingerprints"] = {
                "agentreachguard/v1": finding.fingerprint,
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
                **({"properties": {
                    "coverage": coverage.as_dict(),
                    "control_observations": controls or [],
                    "suppressions": {
                        "suppressed_findings": [f.as_dict() for f in suppressed or []],
                        "diagnostics": suppression_diagnostics or [],
                    },
                }, "invocations": [{
                    "executionSuccessful": not coverage.incomplete,
                    "toolExecutionNotifications": [
                        {"descriptor": {"id": d.diagnostic_id}, "level": "warning",
                         "message": {"text": d.message}, "properties": {
                             "diagnostic_id": d.diagnostic_id, "kind": d.kind,
                             "incomplete": d.incomplete,
                         }} for d in coverage.diagnostics
                    ],
                }]} if coverage is not None else {}),
            }
        ],
    }
