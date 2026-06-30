"""SARIF exporter for detector findings.

Emits SARIF 2.1.0 so findings show up in the GitHub Security tab / CI. Severity
maps onto SARIF result levels.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

    from memory_blackbox.model.records import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    "INFO": "note",
    "LOW": "note",
    "MEDIUM": "warning",
    "HIGH": "error",
    "CRITICAL": "error",
}


def findings_to_sarif(findings: Iterable[Finding], tool_version: str = "0.0.0") -> dict[str, Any]:
    """Render findings as a SARIF 2.1.0 document."""
    findings = list(findings)
    rule_ids = sorted({f.detector_name for f in findings})
    rules = [{"id": rule_id, "name": rule_id} for rule_id in rule_ids]

    results = [
        {
            "ruleId": f.detector_name,
            "level": _LEVEL.get(f.severity.value, "warning"),
            "message": {"text": f.message},
            "properties": {
                "record_id": f.record_id,
                "severity": f.severity.value,
                **f.evidence,
            },
        }
        for f in findings
    ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "memory-blackbox",
                        "version": tool_version,
                        "informationUri": "https://github.com/lavkumarv/agent-forensics",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
