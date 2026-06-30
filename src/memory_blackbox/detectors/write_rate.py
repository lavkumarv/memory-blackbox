"""Detector: write-rate bursts per source.

A source that suddenly writes many memories in a short window is a poisoning
signal (mass injection). This detector keeps a sliding window of write times per
(namespace, source) and fires when the count in the window exceeds a threshold.
State is in-memory and per detector instance.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import TYPE_CHECKING

from memory_blackbox.model.records import Finding, Severity

if TYPE_CHECKING:
    from memory_blackbox.detectors.base import DetectorContext
    from memory_blackbox.model.records import ProvenanceRecord


class WriteRateDetector:
    name = "write_rate"

    def __init__(self, window_seconds: float = 60.0, max_writes: int = 5) -> None:
        self.window_seconds = window_seconds
        self.max_writes = max_writes
        self._history: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def inspect(
        self, record: ProvenanceRecord, content: str, ctx: DetectorContext
    ) -> list[Finding]:
        key = (ctx.namespace, record.source.source_id)
        now = ctx.now.timestamp()
        window = self._history[key]
        window.append(now)
        while window and now - window[0] > self.window_seconds:
            window.popleft()

        if len(window) <= self.max_writes:
            return []
        return [
            Finding(
                detector_name=self.name,
                severity=Severity.MEDIUM,
                record_id=record.record_id,
                message="write-rate burst from a single source",
                evidence={
                    "source_id": record.source.source_id,
                    "writes_in_window": len(window),
                    "window_seconds": self.window_seconds,
                },
            )
        ]
