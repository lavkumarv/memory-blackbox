"""Detector protocol, registry, and the built-in detector pack."""

from __future__ import annotations

from agent_forensics.detectors.base import Detector, DetectorContext
from agent_forensics.detectors.injection_scan import InjectionScanDetector
from agent_forensics.detectors.provenance_missing import ProvenanceMissingDetector
from agent_forensics.detectors.trust_scoring import TrustScoringDetector
from agent_forensics.detectors.unicode_smuggling import UnicodeSmugglingDetector
from agent_forensics.detectors.write_rate import WriteRateDetector

__all__ = [
    "Detector",
    "DetectorContext",
    "InjectionScanDetector",
    "ProvenanceMissingDetector",
    "TrustScoringDetector",
    "UnicodeSmugglingDetector",
    "WriteRateDetector",
    "default_pack",
]


def default_pack() -> list[Detector]:
    """Return a fresh set of the built-in detectors (stateful ones are per-engine)."""
    return [
        ProvenanceMissingDetector(),
        InjectionScanDetector(),
        UnicodeSmugglingDetector(),
        WriteRateDetector(),
        TrustScoringDetector(),
    ]
