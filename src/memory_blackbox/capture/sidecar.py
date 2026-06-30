"""Sidecar proxy for hosted vector databases.

A reverse proxy that sits in front of a hosted vector DB (Pinecone, Qdrant Cloud,
Weaviate, Mongo Atlas). It intercepts upsert (write) and query (read) operations,
records provenance, and forwards the request upstream, returning the response
unchanged. Like the MCP gateway, the core is transport-agnostic and fully testable
offline; binding it to a concrete HTTP/gRPC server is a thin outer layer.

Upserts are *tagged* before forwarding: the provenance record id is attached under
a metadata key so the stored vector carries a back-reference to its ledger entry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memory_blackbox.capture.wrapper import CallCtx

if TYPE_CHECKING:
    from collections.abc import Callable

    from memory_blackbox.capture.engine import Forensics
    from memory_blackbox.capture.wrapper import ReadMap, WriteMap
    from memory_blackbox.model.records import Source

PROVENANCE_TAG = "memory_blackbox_record_id"


class Sidecar:
    """Captures and forwards hosted vector-DB operations."""

    def __init__(
        self,
        forensics: Forensics,
        forward: Callable[[str, dict[str, Any]], Any],
        *,
        namespace: str,
        default_source: Source,
        upsert_ops: dict[str, WriteMap],
        query_ops: dict[str, ReadMap],
    ) -> None:
        self._forensics = forensics
        self._forward = forward
        self._namespace = namespace
        self._default_source = default_source
        self._upsert_ops = upsert_ops
        self._query_ops = query_ops

    def handle(self, op: str, payload: dict[str, Any]) -> Any:
        """Record provenance for ``op`` and forward it upstream unchanged."""
        if op in self._upsert_ops:
            return self._handle_upsert(op, payload)
        if op in self._query_ops:
            return self._handle_query(op, payload)
        return self._forward(op, payload)

    def _handle_upsert(self, op: str, payload: dict[str, Any]) -> Any:
        spec = self._upsert_ops[op]
        # Tag the request before forwarding so the stored vector references the ledger.
        record = self._forensics.record_write(
            spec.content(CallCtx(args=(), kwargs=payload, result=None)),
            self._default_source,
            namespace=self._namespace,
        )
        tagged = {**payload, PROVENANCE_TAG: record.record_id}
        result = self._forward(op, tagged)
        return result

    def _handle_query(self, op: str, payload: dict[str, Any]) -> Any:
        spec = self._query_ops[op]
        result = self._forward(op, payload)
        ctx = CallCtx(args=(), kwargs=payload, result=result)
        self._forensics.record_retrieval(
            spec.query(ctx),
            list(spec.returned(ctx)),
            list(spec.scores(ctx)),
            namespace=self._namespace,
        )
        return result
