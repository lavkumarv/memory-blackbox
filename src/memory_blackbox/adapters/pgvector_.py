"""pgvector adapter.

pgvector has no high-level memory API: writes are ``INSERT ... embedding`` and
reads are ``SELECT ... ORDER BY embedding <=> q``. Rather than intercept arbitrary
SQL, this adapter exposes thin capture helpers an application calls around its own
insert/query (or it can run behind the sidecar). Each helper records the write or
retrieval explicitly.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from memory_blackbox.capture.engine import MemoryBlackbox
    from memory_blackbox.model.records import ProvenanceRecord, RetrievalRecord, Source

BACKEND_NAME = "pgvector"


class PgVectorCapture:
    """Explicit capture helpers for a pgvector-backed store."""

    def __init__(self, blackbox: MemoryBlackbox, namespace: str, default_source: Source) -> None:
        self._blackbox = blackbox
        self._namespace = namespace
        self._default_source = default_source

    def record_insert(
        self, content: str, row_id: str, *, source: Source | None = None
    ) -> ProvenanceRecord:
        """Record a row inserted into the pgvector table."""
        return self._blackbox.record_write(
            content,
            source or self._default_source,
            namespace=self._namespace,
            memory_id=row_id,
        )

    def record_query(
        self, query: str, returned: Sequence[str], scores: Sequence[float] = ()
    ) -> RetrievalRecord:
        """Record a similarity query against the pgvector table."""
        return self._blackbox.record_retrieval(
            query, list(returned), list(scores), namespace=self._namespace
        )
