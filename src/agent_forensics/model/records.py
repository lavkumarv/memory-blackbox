"""Core record models and enums.

These are the immutable units the ledger appends and the DAG links. Ids are uuid7
(time-sortable); timestamps are timezone-aware UTC. The ledger-set fields
(``entry_hash``, ``prev_hash``, ``signature``, ``signer_kid``, ``merkle_leaf``) are
populated on append and must not be supplied by the caller.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_forensics.crypto.hashing import b3
from agent_forensics.model.ids import uuid7_str


def utcnow() -> datetime:
    """Return the current timezone-aware UTC time."""
    return datetime.now(UTC)


def hash_content(content: str) -> str:
    """Return the canonical content hash (``blake3:<hex>``) for string content."""
    return b3(content.encode("utf-8"))


# Field factories typed once so mypy is happy with the defaults below.
_id_factory: Callable[[], str] = uuid7_str
_time_factory: Callable[[], datetime] = utcnow


# --- Enums ------------------------------------------------------------------
class SourceType(StrEnum):
    user_input = "user_input"
    tool_output = "tool_output"
    document_ingest = "document_ingest"
    rag_retrieval = "rag_retrieval"
    web_fetch = "web_fetch"
    file_read = "file_read"
    agent_self = "agent_self"
    inter_agent = "inter_agent"
    system_seed = "system_seed"


class TrustLevel(StrEnum):
    system = "system"
    trusted = "trusted"
    semi_trusted = "semi_trusted"
    untrusted = "untrusted"
    quarantined = "quarantined"


class MemoryType(StrEnum):
    working = "working"
    episodic = "episodic"
    semantic = "semantic"
    procedural = "procedural"
    identity = "identity"


class RecordState(StrEnum):
    active = "active"
    quarantined = "quarantined"
    redacted = "redacted"
    rolled_back = "rolled_back"
    expired = "expired"


class Kind(StrEnum):
    """The ledger row kind for each record type."""

    write = "write"
    retrieval = "retrieval"
    action = "action"
    rollback = "rollback"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# --- Mixins -----------------------------------------------------------------
class LedgerSet(BaseModel):
    """The chain/signature/merkle fields populated by the ledger on append."""

    entry_hash: str | None = None
    prev_hash: str | None = None
    signature: str | None = None
    signer_kid: str | None = None
    merkle_leaf: str | None = None


# --- Records ----------------------------------------------------------------
class Source(BaseModel):
    """The origin of a memory write."""

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(default_factory=_id_factory)
    source_type: SourceType
    locator: str | None = None
    trust_level: TrustLevel = TrustLevel.untrusted
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=_time_factory)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProvenanceRecord(LedgerSet):
    """A memory **write**."""

    model_config = ConfigDict(extra="forbid")

    kind: Kind = Kind.write
    record_id: str = Field(default_factory=_id_factory)
    namespace: str = "default"
    memory_id: str | None = None
    content: str
    content_hash: str = ""
    memory_type: MemoryType = MemoryType.semantic
    source: Source
    derived_from: list[str] = Field(default_factory=list)
    caused_by_retrieval: list[str] = Field(default_factory=list)
    state: RecordState = RecordState.active
    created_at: datetime = Field(default_factory=_time_factory)

    @model_validator(mode="after")
    def _enforce_content_hash(self) -> ProvenanceRecord:
        expected = hash_content(self.content)
        if not self.content_hash:
            self.content_hash = expected
        elif self.content_hash != expected:
            raise ValueError(f"content_hash mismatch: expected {expected}, got {self.content_hash}")
        return self


class RetrievalRecord(LedgerSet):
    """A memory **read**."""

    model_config = ConfigDict(extra="forbid")

    kind: Kind = Kind.retrieval
    retrieval_id: str = Field(default_factory=_id_factory)
    namespace: str = "default"
    query: str
    query_hash: str = ""
    returned: list[str] = Field(default_factory=list)
    scores: list[float] = Field(default_factory=list)
    session_id: str | None = None
    turn_id: str | None = None
    created_at: datetime = Field(default_factory=_time_factory)

    @model_validator(mode="after")
    def _derive_query_hash(self) -> RetrievalRecord:
        if not self.query_hash:
            self.query_hash = hash_content(self.query)
        return self


class ActionRecord(LedgerSet):
    """An agent action attributable to retrieved context."""

    model_config = ConfigDict(extra="forbid")

    kind: Kind = Kind.action
    action_id: str = Field(default_factory=_id_factory)
    namespace: str = "default"
    action_kind: str
    summary: str
    context_retrievals: list[str] = Field(default_factory=list)
    session_id: str | None = None
    turn_id: str | None = None
    created_at: datetime = Field(default_factory=_time_factory)


class RollbackEvent(LedgerSet):
    """An applied rollback, itself appended to the ledger."""

    model_config = ConfigDict(extra="forbid")

    kind: Kind = Kind.rollback
    rollback_id: str = Field(default_factory=_id_factory)
    namespace: str = "default"
    reason: str
    to: str
    scope: str | None = None
    affected: list[str] = Field(default_factory=list)
    applied_at: datetime = Field(default_factory=_time_factory)


class Finding(BaseModel):
    """A detector output."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=_id_factory)
    detector_name: str
    severity: Severity
    record_id: str | None = None
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_time_factory)


# The record types that are appended to the ledger (Finding is not appended).
LedgerRecord = ProvenanceRecord | RetrievalRecord | ActionRecord | RollbackEvent
