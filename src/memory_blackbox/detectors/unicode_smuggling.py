"""Detector: zero-width and bidirectional control characters.

Invisible characters let a payload hide instructions that a human reviewer cannot
see but the model still reads: zero-width spaces/joiners, the BOM, bidi overrides
(the Trojan Source class), and Unicode tag characters used to smuggle ASCII.
Any occurrence is flagged with the offending code points.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from memory_blackbox.model.records import Finding, Severity

if TYPE_CHECKING:
    from memory_blackbox.detectors.base import DetectorContext
    from memory_blackbox.model.records import ProvenanceRecord

# Zero-width and join/format controls: ZWSP, ZWNJ, ZWJ, word joiner, BOM/ZWNBSP.
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
# Bidirectional formatting/override controls (the Trojan Source class).
_BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
_SUSPECT = _ZERO_WIDTH | _BIDI


def _is_smuggled(ch: str) -> bool:
    code = ord(ch)
    return code in _SUSPECT or 0xE0000 <= code <= 0xE007F


class UnicodeSmugglingDetector:
    name = "unicode_smuggling"

    def inspect(
        self, record: ProvenanceRecord, content: str, ctx: DetectorContext
    ) -> list[Finding]:
        offenders = sorted({f"U+{ord(ch):04X}" for ch in content if _is_smuggled(ch)})
        if not offenders:
            return []
        return [
            Finding(
                detector_name=self.name,
                severity=Severity.HIGH,
                record_id=record.record_id,
                message="stored content contains zero-width or bidi control characters",
                evidence={"code_points": offenders},
            )
        ]
