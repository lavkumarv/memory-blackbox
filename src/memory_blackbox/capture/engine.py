"""The Forensics engine facade.

`Forensics` is the single entry point for recording memory activity. Each
`record_*` call builds the appropriate record, runs detectors, appends to the
ledger, and inserts the provenance-DAG edges that later power trace and
blast-radius. Edges follow the forward-influence convention (src -> dst,
origin -> derived):

- a write derived from a parent write:        parent --DERIVED_FROM--> write
- a retrieval that surfaced a stored memory:   memory --RETRIEVED-->     retrieval
- a retrieval that informed a later write:     retrieval --CONTEXTUALIZED--> write
- a retrieval that contributed to an action:   retrieval --CONTRIBUTED_TO--> action
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from memory_blackbox.dag.store import EdgeStore
from memory_blackbox.detectors import default_pack
from memory_blackbox.detectors.base import DetectorContext
from memory_blackbox.ledger.store import LedgerStore
from memory_blackbox.model.edges import EdgeType
from memory_blackbox.model.records import (
    ActionRecord,
    Finding,
    MemoryType,
    ProvenanceRecord,
    RetrievalRecord,
    Source,
)

if TYPE_CHECKING:
    from memory_blackbox.adapters.base import Adapter
    from memory_blackbox.capture.wrapper import ReadMap, WrappedClient, WriteMap
    from memory_blackbox.crypto.keys import KeyPair
    from memory_blackbox.detectors.base import Detector


# Reject absurdly large single memories to bound CPU/memory on the hot path.
# Memory content is attacker-controllable; a multi-GB write would otherwise be
# hashed, embedded, and copied into SQLite unbounded. Generous so real memories
# always fit; configurable per engine.
DEFAULT_MAX_CONTENT_BYTES = 5 * 1024 * 1024  # 5 MiB


class ContentTooLargeError(ValueError):
    """Raised when a memory write exceeds the configured size bound."""


class Forensics:
    """Records memory writes, reads, and actions with signed provenance."""

    def __init__(
        self,
        ledger: LedgerStore,
        dag: EdgeStore,
        detectors: list[Detector] | None = None,
        *,
        max_content_bytes: int = DEFAULT_MAX_CONTENT_BYTES,
    ) -> None:
        self.ledger = ledger
        self.dag = dag
        self.detectors: list[Detector] = default_pack() if detectors is None else detectors
        self.max_content_bytes = max_content_bytes
        self.findings: list[Finding] = []

    @classmethod
    def open(
        cls,
        path: Path | str,
        signer: KeyPair,
        detectors: list[Detector] | None = None,
        *,
        max_content_bytes: int = DEFAULT_MAX_CONTENT_BYTES,
        **ledger_kwargs: object,
    ) -> Forensics:
        """Create a Forensics engine backed by a ledger and DAG at ``path``."""
        ledger = LedgerStore(path, signer, **ledger_kwargs)  # type: ignore[arg-type]
        dag = EdgeStore(ledger.connection)
        return cls(ledger, dag, detectors, max_content_bytes=max_content_bytes)

    # -- recording ----------------------------------------------------------
    def record_write(
        self,
        content: str,
        source: Source,
        *,
        namespace: str = "default",
        memory_id: str | None = None,
        memory_type: MemoryType = MemoryType.semantic,
        derived_from: Sequence[str] = (),
        caused_by_retrieval: Sequence[str] = (),
    ) -> ProvenanceRecord:
        size = len(content.encode("utf-8"))
        if size > self.max_content_bytes:
            raise ContentTooLargeError(
                f"memory content is {size} bytes, exceeds the {self.max_content_bytes}-byte limit"
            )
        record = ProvenanceRecord(
            content=content,
            source=source,
            namespace=namespace,
            memory_id=memory_id,
            memory_type=memory_type,
            derived_from=list(derived_from),
            caused_by_retrieval=list(caused_by_retrieval),
        )
        self._run_detectors(record, content, namespace)
        self.ledger.append(record)
        for parent in record.derived_from:
            self._add_edge(parent, record.record_id, EdgeType.DERIVED_FROM)
        for retrieval_id in record.caused_by_retrieval:
            self._add_edge(retrieval_id, record.record_id, EdgeType.CONTEXTUALIZED)
        return record

    def record_retrieval(
        self,
        query: str,
        returned: Sequence[str],
        scores: Sequence[float] = (),
        *,
        namespace: str = "default",
        session_id: str | None = None,
        turn_id: str | None = None,
    ) -> RetrievalRecord:
        record = RetrievalRecord(
            query=query,
            returned=list(returned),
            scores=list(scores),
            namespace=namespace,
            session_id=session_id,
            turn_id=turn_id,
        )
        self.ledger.append(record)
        for memory_id in record.returned:
            self._add_edge(memory_id, record.retrieval_id, EdgeType.RETRIEVED)
        return record

    def record_action(
        self,
        action_kind: str,
        summary: str,
        context_retrievals: Sequence[str] = (),
        *,
        namespace: str = "default",
        session_id: str | None = None,
        turn_id: str | None = None,
    ) -> ActionRecord:
        record = ActionRecord(
            action_kind=action_kind,
            summary=summary,
            context_retrievals=list(context_retrievals),
            namespace=namespace,
            session_id=session_id,
            turn_id=turn_id,
        )
        self.ledger.append(record)
        for retrieval_id in record.context_retrievals:
            self._add_edge(retrieval_id, record.action_id, EdgeType.CONTRIBUTED_TO)
        return record

    def wrap(
        self,
        client: object,
        *,
        namespace: str,
        default_source: Source,
        write_methods: dict[str, WriteMap],
        read_methods: dict[str, ReadMap],
    ) -> WrappedClient:
        """Wrap a memory backend so its calls are captured (see capture.wrapper)."""
        from memory_blackbox.capture.wrapper import WrappedClient

        return WrappedClient(
            self,
            client,
            namespace=namespace,
            default_source=default_source,
            write_methods=write_methods,
            read_methods=read_methods,
        )

    def wrap_adapter(
        self, client: object, adapter: Adapter, *, namespace: str, default_source: Source
    ) -> WrappedClient:
        """Wrap ``client`` using a backend ``adapter``'s write/read mappings."""
        return self.wrap(
            client,
            namespace=namespace,
            default_source=default_source,
            write_methods=adapter.write_methods,
            read_methods=adapter.read_methods,
        )

    # -- internals ----------------------------------------------------------
    def _run_detectors(self, record: ProvenanceRecord, content: str, namespace: str) -> None:
        if not self.detectors:
            return
        ctx = DetectorContext(namespace=namespace, now=datetime.now(UTC))
        for detector in self.detectors:
            self.findings.extend(detector.inspect(record, content, ctx))

    def _add_edge(self, src: str, dst: str, edge_type: EdgeType) -> None:
        """Add a lineage edge, skipping endpoints not tracked in the ledger."""
        if self.ledger.get(src) is None or self.ledger.get(dst) is None:
            return
        self.dag.add_edge(src, dst, edge_type)

    def detector_names(self) -> Iterable[str]:
        return (d.name for d in self.detectors)
