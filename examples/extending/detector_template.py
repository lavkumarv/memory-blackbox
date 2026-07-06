"""Template: write a detector in ~20 lines.

A detector inspects each memory write and returns findings. Copy this file, give it
a unique ``name``, implement ``inspect``, and either pass an instance to
``MemoryBlackbox(..., detectors=[MyDetector()])`` or add it to a detector pack.

Run the smoke check at the bottom:  python examples/extending/detector_template.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from memory_blackbox.model.records import Finding, Severity

if TYPE_CHECKING:
    from memory_blackbox.detectors.base import DetectorContext
    from memory_blackbox.model.records import ProvenanceRecord


class ShoutingDetector:
    """Example: flag memory written in ALL CAPS (replace with your real signal)."""

    name = "shouting"  # must be unique across the active pack

    def inspect(
        self, record: ProvenanceRecord, content: str, ctx: DetectorContext
    ) -> list[Finding]:
        letters = [c for c in content if c.isalpha()]
        if len(letters) >= 10 and all(c.isupper() for c in letters):
            return [
                Finding(
                    detector_name=self.name,
                    severity=Severity.LOW,
                    record_id=record.record_id,
                    message="memory content is entirely uppercase",
                    evidence={"length": len(content)},
                )
            ]
        return []


if __name__ == "__main__":
    import tempfile
    from pathlib import Path

    from memory_blackbox.capture.engine import MemoryBlackbox
    from memory_blackbox.crypto import keys
    from memory_blackbox.model.records import Source, SourceType

    with tempfile.TemporaryDirectory() as tmp:
        blackbox = MemoryBlackbox.open(
            Path(tmp) / "l.db", keys.generate(), detectors=[ShoutingDetector()]
        )
        blackbox.record_write("THIS IS SHOUTING", Source(source_type=SourceType.user_input))
        blackbox.record_write("this is calm", Source(source_type=SourceType.user_input))
        print("findings:", [(f.detector_name, f.severity.value) for f in blackbox.findings])
