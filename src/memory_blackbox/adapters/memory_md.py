"""memory.md adapter: watch agent memory files for out-of-band edits.

Files like ``MEMORY.md``, ``CLAUDE.md``, and ``AGENTS.md`` are agent memory that
anything on the machine can write -- the CVE-2026-21852 postinstall-poisoning
surface. This adapter snapshots the watched files and, on each scan, records a
provenance write for any file that changed, attributing it to the file path so a
poisoning edit is captured and traceable even though it bypassed the agent.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from memory_blackbox.crypto.hashing import b3
from memory_blackbox.model.records import MemoryType, Source, SourceType

if TYPE_CHECKING:
    from memory_blackbox.capture.engine import Forensics
    from memory_blackbox.model.records import ProvenanceRecord

DEFAULT_FILES = ("MEMORY.md", "CLAUDE.md", "AGENTS.md")
BACKEND_NAME = "memory_md"


class MemoryMdAdapter:
    """Watches agent memory files and records changes as provenance writes."""

    def __init__(
        self,
        forensics: Forensics,
        root: Path | str,
        *,
        namespace: str = "memory_md",
        filenames: tuple[str, ...] = DEFAULT_FILES,
    ) -> None:
        self._forensics = forensics
        self._root = Path(root)
        self._namespace = namespace
        self._filenames = filenames
        self._snapshots: dict[str, str] = {}

    def _paths(self) -> list[Path]:
        return [self._root / name for name in self._filenames]

    def baseline(self) -> None:
        """Record the current contents as the trusted baseline without flagging."""
        for path in self._paths():
            if path.exists():
                self._snapshots[str(path)] = b3(path.read_bytes())

    def scan(self) -> list[ProvenanceRecord]:
        """Record a write for each watched file that changed since the last scan."""
        records: list[ProvenanceRecord] = []
        for path in self._paths():
            if not path.exists():
                continue
            # Don't load a hostile multi-GB memory file into memory; the engine
            # enforces the same bound, but check before reading at all.
            if path.stat().st_size > self._forensics.max_content_bytes:
                continue
            content = path.read_text(encoding="utf-8")
            digest = b3(content.encode("utf-8"))
            if self._snapshots.get(str(path)) == digest:
                continue
            self._snapshots[str(path)] = digest
            source = Source(
                source_id=str(path),
                source_type=SourceType.file_read,
                locator=str(path),
            )
            records.append(
                self._forensics.record_write(
                    content,
                    source,
                    namespace=self._namespace,
                    memory_id=str(path),
                    memory_type=MemoryType.procedural,
                )
            )
        return records
