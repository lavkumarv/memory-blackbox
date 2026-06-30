"""Detector: secrets and PII in stored memory content.

Agent memory routinely captures credentials and personal data. Flagging them is
both a security signal (a leaked key in memory is an incident) and the foundation
of the compliance story (a tamper-evident record of *what sensitive data the agent
held and when*). Matched categories and counts are reported — never the secret
value itself, so the finding does not re-leak it.

All patterns are anchored and linear (no catastrophic backtracking).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from memory_blackbox.model.records import Finding, Severity

if TYPE_CHECKING:
    from memory_blackbox.detectors.base import DetectorContext
    from memory_blackbox.model.records import ProvenanceRecord

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("github_token", re.compile(r"\bgh[posru]_[A-Za-z0-9]{20,}\b")),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*['\"]?[A-Za-z0-9/+_-]{16,}"
        ),
    ),
]

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]


class SecretsPiiDetector:
    name = "secrets_pii"

    def inspect(
        self, record: ProvenanceRecord, content: str, ctx: DetectorContext
    ) -> list[Finding]:
        secrets = {
            name: len(p.findall(content)) for name, p in _SECRET_PATTERNS if p.search(content)
        }
        pii = {name: len(p.findall(content)) for name, p in _PII_PATTERNS if p.search(content)}
        if not secrets and not pii:
            return []
        severity = Severity.HIGH if secrets else Severity.MEDIUM
        kind = "secret material" if secrets else "personal data"
        return [
            Finding(
                detector_name=self.name,
                severity=severity,
                record_id=record.record_id,
                message=f"stored content contains {kind} (consider redaction)",
                # Categories and counts only -- never the matched value.
                evidence={"secrets": secrets, "pii": pii},
            )
        ]
