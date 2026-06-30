"""Detector: imperative-override and instruction-smuggling patterns.

Heuristic regex scan for the phrasings memory-poisoning payloads use to hijack a
later agent turn (ignore previous instructions, role reassignment, prompt
exfiltration, tool-abuse imperatives). Tuned for precision: benign prose should
not match. Each match is reported with the matched span as evidence.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from memory_blackbox.model.records import Finding, Severity

if TYPE_CHECKING:
    from memory_blackbox.detectors.base import DetectorContext
    from memory_blackbox.model.records import ProvenanceRecord

_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(the\s+)?(above|previous|prior|earlier)\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\s+(a|an|the)\b", re.IGNORECASE),
    re.compile(r"\b(reveal|print|show|leak)\s+(your\s+)?(system\s+)?prompt\b", re.IGNORECASE),
    re.compile(r"\b(system|developer)\s*(prompt|message)\s*:", re.IGNORECASE),
    re.compile(r"\boverride\s+(all\s+)?(safety|security|previous)\b", re.IGNORECASE),
    re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE),
    re.compile(r"\bsend\s+(all\s+)?(the\s+)?(passwords?|secrets?|credentials?)\b", re.IGNORECASE),
    re.compile(r"</?(system|instructions?)>", re.IGNORECASE),
]


class InjectionScanDetector:
    name = "injection_scan"

    def inspect(
        self, record: ProvenanceRecord, content: str, ctx: DetectorContext
    ) -> list[Finding]:
        matches = [m.group(0) for p in _PATTERNS if (m := p.search(content))]
        if not matches:
            return []
        return [
            Finding(
                detector_name=self.name,
                severity=Severity.HIGH,
                record_id=record.record_id,
                message="stored content contains instruction-override / smuggling patterns",
                evidence={"matches": matches},
            )
        ]
