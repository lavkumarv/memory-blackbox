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
    from memory_blackbox.capture.engine import MemoryBlackbox
    from memory_blackbox.model.records import ProvenanceRecord

DEFAULT_FILES = ("MEMORY.md", "CLAUDE.md", "AGENTS.md")
BACKEND_NAME = "memory_md"


class MemoryMdAdapter:
    """Watches agent memory files and records changes as provenance writes."""

    def __init__(
        self,
        blackbox: MemoryBlackbox,
        root: Path | str,
        *,
        namespace: str = "memory_md",
        filenames: tuple[str, ...] = DEFAULT_FILES,
    ) -> None:
        self._blackbox = blackbox
        self._root = Path(root)
        self._namespace = namespace
        self._filenames = filenames
        self._snapshots: dict[str, str] = {}

    def _paths(self) -> list[Path]:
        return [self._root / name for name in self._filenames]

    def baseline(self) -> list[ProvenanceRecord]:
        """Establish the trusted baseline for each watched file.

        The ledger, not the file, is the trusted state: if it already holds a
        write for a file, that write's hash becomes the baseline, so an edit made
        while no process was watching is flagged by the next ``scan()``. A file
        the ledger has never seen is recorded once, so the baseline outlives this
        process. Returns the writes recorded for previously unseen files.
        """
        records: list[ProvenanceRecord] = []
        for path in self._paths():
            if not path.exists():
                continue
            known = self._blackbox.ledger.last_write_hash(self._namespace, str(path))
            if known is not None:
                self._snapshots[str(path)] = known
            elif (record := self._record_if_changed(path)) is not None:
                records.append(record)
        return records

    def scan(self) -> list[ProvenanceRecord]:
        """Record a write for each watched file that changed since the last scan."""
        records: list[ProvenanceRecord] = []
        for path in self._paths():
            if path.exists() and (record := self._record_if_changed(path)) is not None:
                records.append(record)
        return records

    def _record_if_changed(self, path: Path) -> ProvenanceRecord | None:
        # Don't load a hostile multi-GB memory file into memory; the engine
        # enforces the same bound, but check before reading at all.
        if path.stat().st_size > self._blackbox.max_content_bytes:
            return None
        content = path.read_text(encoding="utf-8")
        digest = b3(content.encode("utf-8"))
        if self._snapshots.get(str(path)) == digest:
            return None
        self._snapshots[str(path)] = digest
        source = Source(
            source_id=str(path),
            source_type=SourceType.file_read,
            locator=str(path),
        )
        return self._blackbox.record_write(
            content,
            source,
            namespace=self._namespace,
            memory_id=str(path),
            memory_type=MemoryType.procedural,
        )
