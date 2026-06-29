"""Template: write a detector in ~20 lines.

A detector inspects each memory write and returns findings. Copy this file, give it
a unique ``name``, implement ``inspect``, and either pass an instance to
``Forensics(..., detectors=[MyDetector()])`` or add it to a detector pack.

Run the smoke check at the bottom:  python examples/extending/detector_template.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_forensics.model.records import Finding, Severity

if TYPE_CHECKING:
    from agent_forensics.detectors.base import DetectorContext
    from agent_forensics.model.records import ProvenanceRecord


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

    from agent_forensics.capture.engine import Forensics
    from agent_forensics.crypto import keys
    from agent_forensics.model.records import Source, SourceType

    with tempfile.TemporaryDirectory() as tmp:
        forensics = Forensics.open(
            Path(tmp) / "l.db", keys.generate(), detectors=[ShoutingDetector()]
        )
        forensics.record_write("THIS IS SHOUTING", Source(source_type=SourceType.user_input))
        forensics.record_write("this is calm", Source(source_type=SourceType.user_input))
        print("findings:", [(f.detector_name, f.severity.value) for f in forensics.findings])
