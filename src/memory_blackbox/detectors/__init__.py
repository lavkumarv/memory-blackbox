"""Detector protocol, registry, and the built-in detector pack."""

from __future__ import annotations

from memory_blackbox.detectors.base import Detector, DetectorContext
from memory_blackbox.detectors.drift import DriftDetector
from memory_blackbox.detectors.injection_scan import InjectionScanDetector
from memory_blackbox.detectors.provenance_missing import ProvenanceMissingDetector
from memory_blackbox.detectors.secrets_pii import SecretsPiiDetector
from memory_blackbox.detectors.trust_scoring import TrustScoringDetector
from memory_blackbox.detectors.unicode_smuggling import UnicodeSmugglingDetector
from memory_blackbox.detectors.write_rate import WriteRateDetector

__all__ = [
    "Detector",
    "DetectorContext",
    "DriftDetector",
    "InjectionScanDetector",
    "ProvenanceMissingDetector",
    "SecretsPiiDetector",
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
        SecretsPiiDetector(),
        WriteRateDetector(),
        TrustScoringDetector(),
        DriftDetector(),
    ]
