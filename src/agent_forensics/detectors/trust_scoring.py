"""Detector: running trust score per source.

Maintains a posterior trust score per source, seeded from the source's declared
prior. Anomalous observations (untrusted/quarantined level, or no traceable
origin) multiply the posterior down by a fixed penalty; clean observations let it
recover toward 1. The update is monotonic non-increasing under repeated anomalies,
and each finding exposes both prior and posterior.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_forensics.model.records import Finding, Severity, TrustLevel

if TYPE_CHECKING:
    from agent_forensics.detectors.base import DetectorContext
    from agent_forensics.model.records import ProvenanceRecord

_ANOMALOUS_LEVELS = {TrustLevel.untrusted, TrustLevel.quarantined}


class TrustScoringDetector:
    name = "trust_scoring"

    def __init__(self, penalty: float = 0.25, recovery: float = 0.1) -> None:
        self.penalty = penalty
        self.recovery = recovery
        self._posterior: dict[str, float] = {}

    def _severity(self, posterior: float) -> Severity:
        if posterior < 0.3:
            return Severity.HIGH
        if posterior < 0.6:
            return Severity.MEDIUM
        return Severity.INFO

    def inspect(
        self, record: ProvenanceRecord, content: str, ctx: DetectorContext
    ) -> list[Finding]:
        source = record.source
        prior = self._posterior.get(source.source_id, source.trust_score)
        anomalous = source.trust_level in _ANOMALOUS_LEVELS or source.locator is None
        if anomalous:
            posterior = prior * (1.0 - self.penalty)
        else:
            posterior = min(1.0, prior + (1.0 - prior) * self.recovery)
        self._posterior[source.source_id] = posterior

        if not anomalous:
            return []
        return [
            Finding(
                detector_name=self.name,
                severity=self._severity(posterior),
                record_id=record.record_id,
                message="source trust score decayed after an anomalous write",
                evidence={
                    "source_id": source.source_id,
                    "prior": round(prior, 6),
                    "posterior": round(posterior, 6),
                },
            )
        ]

    def score(self, source_id: str) -> float | None:
        """Return the current posterior trust score for a source, if seen."""
        return self._posterior.get(source_id)
