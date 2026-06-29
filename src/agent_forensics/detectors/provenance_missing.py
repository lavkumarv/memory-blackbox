"""Detector: a write that lacks a traceable origin.

External content (ingested documents, web fetches, tool output, RAG results)
should carry a locator pointing at where it came from. A write from such a source
with no locator is a provenance gap and is flagged HIGH; for self/user/system
sources a missing locator is expected and downgraded to INFO.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_forensics.model.records import Finding, Severity, SourceType

if TYPE_CHECKING:
    from agent_forensics.detectors.base import DetectorContext
    from agent_forensics.model.records import ProvenanceRecord

_EXTERNAL = {
    SourceType.document_ingest,
    SourceType.web_fetch,
    SourceType.file_read,
    SourceType.rag_retrieval,
    SourceType.tool_output,
    SourceType.inter_agent,
}


class ProvenanceMissingDetector:
    name = "provenance_missing"

    def inspect(
        self, record: ProvenanceRecord, content: str, ctx: DetectorContext
    ) -> list[Finding]:
        source = record.source
        if source.locator:
            return []
        external = source.source_type in _EXTERNAL
        severity = Severity.HIGH if external else Severity.INFO
        return [
            Finding(
                detector_name=self.name,
                severity=severity,
                record_id=record.record_id,
                message="write has no traceable origin (missing source locator)",
                evidence={
                    "source_type": source.source_type.value,
                    "trust_level": source.trust_level.value,
                },
            )
        ]
