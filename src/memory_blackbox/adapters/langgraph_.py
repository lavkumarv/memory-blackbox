"""LangGraph adapter: a checkpointer that records and audits every checkpoint.

LangGraph agents resume from their checkpointer, so a checkpoint edited in the
store (SQLite file, Postgres table, Redis key) is memory the agent will trust on
its next step. ``BlackboxCheckpointSaver`` wraps any ``BaseCheckpointSaver`` and,
after each ``put`` / ``put_writes``, reads the checkpoint back from the store and
records it as a signed provenance write. Recording what the store returns, not
what was passed in, means the audit compares like with like whatever the backend
adds on save (merged metadata, split channel blobs).

``audit_checkpoints`` then reconciles the store against the ledger in both
directions:

- every checkpoint and pending-write group in the store must match its newest
  ledger write (catches content, metadata, reorder and replay edits), and must
  have one at all (catches forged checkpoints that never went through capture);
- every checkpoint the ledger holds as live must still be in the store (catches
  middle deletion and tail truncation).

Deletions made through the wrapper (``delete_thread``, ``prune``,
``delete_for_runs``) are recorded as signed tombstones, but only for checkpoints
that were present just before the call, so a legitimate prune cannot launder an
earlier out-of-band deletion. ``copy_thread`` refuses to copy a source thread
that fails the audit. With ``verify_on_read=True`` the wrapper also checks each
checkpoint it serves and raises ``CheckpointIntegrityError`` instead of letting
the agent resume from an edited one; deletions are caught by the audit only.

This module imports ``langgraph-checkpoint`` (the ``langgraph`` extra).
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import math
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum, StrEnum
from typing import TYPE_CHECKING, Any

import orjson
from langgraph.checkpoint.base import (
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    DeltaChannelHistory,
)

from memory_blackbox.crypto.hashing import b3
from memory_blackbox.ledger.chain import verify_chain
from memory_blackbox.model.records import (
    MemoryType,
    Source,
    SourceType,
    TrustLevel,
    hash_content,
)

if TYPE_CHECKING:
    from langchain_core.runnables import RunnableConfig

    from memory_blackbox.capture.engine import MemoryBlackbox
    from memory_blackbox.ledger.store import LedgerStore

BACKEND_NAME = "langgraph"
DEFAULT_NAMESPACE = "langgraph"

_CHECKPOINT = "checkpoint"
_WRITES = "writes"
_DELETED = "deleted"
_INT64 = 2**63
_HEAD_CHARS = 65_536
_SCANNED_CAP = 50_000  # per thread; past it the set resets and history is rescanned once


class CheckpointIntegrityError(RuntimeError):
    """A checkpoint does not match what the ledger recorded for it."""


class IssueKind(StrEnum):
    TAMPERED = "tampered"  # present, but differs from its newest ledger write
    FORGED = "forged"  # present, but the ledger never recorded it (or recorded it deleted)
    MISSING = "missing"  # recorded live in the ledger, gone from the store
    LEDGER = "ledger"  # the ledger itself failed chain verification


@dataclass(frozen=True, slots=True)
class CheckpointIssue:
    kind: IssueKind
    memory_id: str
    detail: str


@dataclass(frozen=True, slots=True)
class CheckpointAuditReport:
    """Result of reconciling a checkpoint store against the ledger."""

    checked: int
    issues: tuple[CheckpointIssue, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.issues


# -- canonical rendering ----------------------------------------------------
def _dumps(obj: Any) -> str:
    return orjson.dumps(obj, option=orjson.OPT_SORT_KEYS).decode("utf-8")


def _type_name(value: object) -> str:
    cls = type(value)
    return f"{cls.__module__}.{cls.__qualname__}"


def _canon(value: Any, serde: Any) -> Any:
    """Render ``value`` as deterministic JSON-able data.

    Sets are sorted, so the rendering does not depend on hash seeds; pydantic
    models (LangChain messages) and dataclasses are expanded field by field, so
    the recorded content stays readable for forensics and detectors. Anything
    else is bound by a digest of its serialized bytes.
    """
    if value is None or isinstance(value, bool | str):
        return value
    if isinstance(value, int):
        return value if -_INT64 <= value < _INT64 else {"$int": str(value)}
    if isinstance(value, float):
        return value if math.isfinite(value) else {"$float": repr(value)}
    if isinstance(value, bytes | bytearray):
        return {"$bytes": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, Mapping):
        return {str(k): _canon(v, serde) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_canon(v, serde) for v in value]
    if isinstance(value, set | frozenset):
        items = [_canon(v, serde) for v in value]
        return {"$set": sorted(items, key=_dumps)}
    if isinstance(value, Enum):
        return _canon(value.value, serde)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if not isinstance(value, type):
        model_dump = getattr(value, "model_dump", None)
        if callable(model_dump):
            return {"$type": _type_name(value), "$value": _canon(model_dump(), serde)}
        if dataclasses.is_dataclass(value):
            fields = {f.name: getattr(value, f.name) for f in dataclasses.fields(value)}
            return {"$type": _type_name(value), "$value": _canon(fields, serde)}
    try:
        _, data = serde.dumps_typed(value)
    except Exception:
        return {"$type": _type_name(value)}
    return {"$type": _type_name(value), "$serde": b3(data)}


# -- identity ---------------------------------------------------------------
def _ids(config: RunnableConfig) -> tuple[str, str, str]:
    conf = config["configurable"]
    return str(conf["thread_id"]), str(conf.get("checkpoint_ns", "")), str(conf["checkpoint_id"])


def checkpoint_memory_id(thread_id: str, checkpoint_ns: str, checkpoint_id: str) -> str:
    """The ledger ``memory_id`` of a checkpoint."""
    return _dumps([_CHECKPOINT, thread_id, checkpoint_ns, checkpoint_id])


def writes_memory_id(thread_id: str, checkpoint_ns: str, checkpoint_id: str, task_id: str) -> str:
    """The ledger ``memory_id`` of one task's pending writes on a checkpoint."""
    return _dumps([_WRITES, thread_id, checkpoint_ns, checkpoint_id, task_id])


def _thread_source(memory_id: str) -> Source:
    """The default source of a checkpoint record: the agent runtime, per thread.

    One source per thread keeps the per-source detectors (trust scoring, write rate)
    scoped to a conversation instead of the whole checkpointer.
    """
    _, thread_id, ns, *_ = orjson.loads(memory_id)
    return Source(
        source_id=f"langgraph:{thread_id}",
        source_type=SourceType.agent_self,
        locator=f"langgraph://{thread_id}/{ns}",
        trust_level=TrustLevel.semi_trusted,
    )


def _thread_of(memory_id: str) -> str | None:
    try:
        parts = orjson.loads(memory_id)
    except orjson.JSONDecodeError:
        return None
    if isinstance(parts, list) and len(parts) >= 4 and parts[0] in (_CHECKPOINT, _WRITES):
        return str(parts[1])
    return None


def _checkpoint_of(memory_id: str) -> str:
    """The checkpoint memory_id a writes memory_id belongs to (itself otherwise)."""
    parts = orjson.loads(memory_id)
    return checkpoint_memory_id(parts[1], parts[2], parts[3]) if parts[0] == _WRITES else memory_id


# -- tuple -> recorded content ----------------------------------------------
def _checkpoint_content(tup: CheckpointTuple, serde: Any) -> tuple[str, str]:
    thread_id, ns, checkpoint_id = _ids(tup.config)
    parent = tup.parent_config["configurable"].get("checkpoint_id") if tup.parent_config else None
    content = _dumps(
        {
            "langgraph": _CHECKPOINT,
            "thread_id": thread_id,
            "checkpoint_ns": ns,
            "checkpoint_id": checkpoint_id,
            "parent_checkpoint_id": parent,
            "checkpoint": _canon(tup.checkpoint, serde),
            "metadata": _canon(tup.metadata, serde),
        }
    )
    return checkpoint_memory_id(thread_id, ns, checkpoint_id), content


def _writes_contents(tup: CheckpointTuple, serde: Any) -> dict[str, str]:
    """One content per task id with pending writes on ``tup``, keyed by memory_id."""
    thread_id, ns, checkpoint_id = _ids(tup.config)
    by_task: dict[str, list[Any]] = {}
    for task_id, channel, value in tup.pending_writes or ():
        by_task.setdefault(str(task_id), []).append([channel, _canon(value, serde)])
    return {
        writes_memory_id(thread_id, ns, checkpoint_id, task_id): _dumps(
            {
                "langgraph": _WRITES,
                "thread_id": thread_id,
                "checkpoint_ns": ns,
                "checkpoint_id": checkpoint_id,
                "task_id": task_id,
                "writes": writes,
            }
        )
        for task_id, writes in by_task.items()
    }


def _strings(value: Any) -> Iterator[str]:
    """The string leaves of canonical data, skipping the type markers ``_canon`` adds."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if key not in ("$type", "$serde"):
                yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _memory_values(content: str) -> tuple[str, Any] | None:
    """``(thread_id, values)`` holding the memory a record carries, or None for a tombstone."""
    data = orjson.loads(content)
    if data.get("langgraph") == _CHECKPOINT:
        return data["thread_id"], data["checkpoint"].get("channel_values")
    if data.get("langgraph") == _WRITES:
        return data["thread_id"], [value for _channel, value in data["writes"]]
    return None


def _bounded(content: str, limit: int) -> str:
    """The content as recorded, within the ledger's ``limit`` bytes.

    Oversized content (a long chat history) is recorded as its digest, its size and
    a readable head. The digest covers the full rendering, so any change to the
    checkpoint still changes the recorded hash; only the forensic copy is shortened.
    """
    size = len(content.encode("utf-8"))
    if size <= limit:
        return content
    # JSON-escaping can take 6 bytes per character, so this head always fits.
    head = content[: min(_HEAD_CHARS, limit // 8)]
    oversized = {"bytes": size, "digest": hash_content(content), "head": head}
    return _dumps({"$oversized": oversized})


def _tuple_hashes(tup: CheckpointTuple, serde: Any, limit: int) -> dict[str, str]:
    """memory_id -> recorded content hash for a checkpoint and each of its write groups."""
    mid, content = _checkpoint_content(tup, serde)
    hashes = {mid: hash_content(_bounded(content, limit))}
    for wid, c in _writes_contents(tup, serde).items():
        hashes[wid] = hash_content(_bounded(c, limit))
    return hashes


def _tombstone(memory_id: str, operation: str) -> str:
    return _dumps({"langgraph": _DELETED, "memory_id": memory_id, "by": operation})


# -- ledger side ------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _LedgerEntry:
    content_hash: str
    deleted: bool


def _ledger_entries(
    ledger: LedgerStore, namespace: str, thread_ids: set[str] | None
) -> dict[str, _LedgerEntry]:
    """Newest ledger write per checkpoint/writes memory_id in ``namespace``."""
    newest: dict[str, _LedgerEntry] = {}
    rows = ledger.query(
        "SELECT payload_json FROM ledger WHERE kind = 'write' AND namespace = ? ORDER BY seq ASC",
        (namespace,),
    )
    for row in rows:
        payload = orjson.loads(row["payload_json"])
        memory_id = payload.get("memory_id")
        if not memory_id:
            continue
        thread = _thread_of(memory_id)
        if thread is None or (thread_ids is not None and thread not in thread_ids):
            continue
        content = payload.get("content", "")
        # Tombstones sort "by" first; check that before parsing large checkpoint content.
        deleted = (
            content.startswith('{"by":') and orjson.loads(content).get("langgraph") == _DELETED
        )
        newest[memory_id] = _LedgerEntry(payload["content_hash"], deleted)
    return newest


def _reconcile(present: dict[str, str], recorded: dict[str, _LedgerEntry]) -> list[CheckpointIssue]:
    issues: list[CheckpointIssue] = []
    for memory_id, digest in sorted(present.items()):
        entry = recorded.get(memory_id)
        if entry is None:
            issues.append(
                CheckpointIssue(IssueKind.FORGED, memory_id, "in the store but never recorded")
            )
        elif entry.deleted:
            issues.append(
                CheckpointIssue(
                    IssueKind.FORGED, memory_id, "recorded as deleted, back in the store"
                )
            )
        elif entry.content_hash != digest:
            issues.append(
                CheckpointIssue(
                    IssueKind.TAMPERED,
                    memory_id,
                    f"store hash {digest} != recorded {entry.content_hash}",
                )
            )
    missing = {mid for mid, e in recorded.items() if not e.deleted and mid not in present}
    for memory_id in sorted(missing):
        # A missing checkpoint takes its pending writes with it; report it once.
        if _checkpoint_of(memory_id) != memory_id and _checkpoint_of(memory_id) in missing:
            continue
        issues.append(
            CheckpointIssue(IssueKind.MISSING, memory_id, "recorded live, gone from the store")
        )
    return issues


def _list_configs(thread_ids: Sequence[str] | None) -> list[RunnableConfig | None]:
    if thread_ids is None:
        return [None]
    return [{"configurable": {"thread_id": t}} for t in thread_ids]


def _present(
    saver: BaseCheckpointSaver[Any], thread_ids: Sequence[str] | None, limit: int
) -> dict[str, str]:
    present: dict[str, str] = {}
    for config in _list_configs(thread_ids):
        for tup in saver.list(config):
            present.update(_tuple_hashes(tup, saver.serde, limit))
    return present


async def _apresent(
    saver: BaseCheckpointSaver[Any], thread_ids: Sequence[str] | None, limit: int
) -> dict[str, str]:
    present: dict[str, str] = {}
    for config in _list_configs(thread_ids):
        async for tup in saver.alist(config):
            present.update(_tuple_hashes(tup, saver.serde, limit))
    return present


def _report(
    present: dict[str, str],
    blackbox: MemoryBlackbox,
    namespace: str,
    thread_ids: Sequence[str] | None,
    verify_ledger: bool,
) -> CheckpointAuditReport:
    issues: list[CheckpointIssue] = []
    if verify_ledger:
        with blackbox.ledger.lock:  # a consistent chain while the agent keeps writing
            chain = verify_chain(blackbox.ledger.connection, blackbox.ledger.public_key)
        if not chain.ok and chain.divergence is not None:
            d = chain.divergence
            issues.append(
                CheckpointIssue(
                    IssueKind.LEDGER, d.record_id, f"{d.kind} at seq {d.seq}: {d.detail}"
                )
            )
    scope = set(thread_ids) if thread_ids is not None else None
    recorded = _ledger_entries(blackbox.ledger, namespace, scope)
    issues.extend(_reconcile(present, recorded))
    return CheckpointAuditReport(checked=len(present), issues=tuple(issues))


def audit_checkpoints(
    saver: BaseCheckpointSaver[Any],
    blackbox: MemoryBlackbox,
    *,
    namespace: str = DEFAULT_NAMESPACE,
    thread_ids: Sequence[str] | None = None,
    verify_ledger: bool = True,
) -> CheckpointAuditReport:
    """Reconcile ``saver``'s checkpoints (all threads, or ``thread_ids``) with the ledger.

    ``saver`` can be the wrapper or the raw store it wraps, so a separate audit
    job can open the store directly. With ``verify_ledger`` the ledger's own hash
    chain is verified first, since the audit is only as good as the ledger.
    """
    inner = saver.inner if isinstance(saver, BlackboxCheckpointSaver) else saver
    present = _present(inner, thread_ids, blackbox.max_content_bytes)
    return _report(present, blackbox, namespace, thread_ids, verify_ledger)


async def aaudit_checkpoints(
    saver: BaseCheckpointSaver[Any],
    blackbox: MemoryBlackbox,
    *,
    namespace: str = DEFAULT_NAMESPACE,
    thread_ids: Sequence[str] | None = None,
    verify_ledger: bool = True,
) -> CheckpointAuditReport:
    """Async ``audit_checkpoints``, for savers that only list asynchronously."""
    inner = saver.inner if isinstance(saver, BlackboxCheckpointSaver) else saver
    present = await _apresent(inner, thread_ids, blackbox.max_content_bytes)
    return _report(present, blackbox, namespace, thread_ids, verify_ledger)


# -- the wrapper ------------------------------------------------------------
class BlackboxCheckpointSaver(BaseCheckpointSaver[Any]):
    """A LangGraph checkpointer that records every checkpoint in the ledger.

    Use it wherever a checkpointer goes::

        saver = BlackboxCheckpointSaver(SqliteSaver(conn), blackbox)
        graph = builder.compile(checkpointer=saver)
        ...
        assert saver.audit().ok
    """

    def __init__(
        self,
        inner: BaseCheckpointSaver[Any],
        blackbox: MemoryBlackbox,
        *,
        namespace: str = DEFAULT_NAMESPACE,
        source: Source | None = None,
        verify_on_read: bool = False,
    ) -> None:
        super().__init__(serde=inner.serde)
        self.inner = inner
        self._blackbox = blackbox
        self._namespace = namespace
        self._verify_on_read = verify_on_read
        # Per-thread hashes of memory strings the detectors have already scanned.
        self._scanned: dict[str, set[int]] = {}
        self._scanned_lock = threading.Lock()
        self._source = source

    def __getattr__(self, name: str) -> Any:
        # Backend extras (setup(), conn, ...) pass through to the wrapped saver.
        if name == "inner":
            raise AttributeError(name)
        return getattr(self.inner, name)

    @property
    def config_specs(self) -> list[Any]:
        return list(self.inner.config_specs)

    def get_next_version(self, current: Any, channel: None) -> Any:
        return self.inner.get_next_version(current, channel)

    def with_allowlist(self, extra_allowlist: Any) -> BlackboxCheckpointSaver:
        inner = self.inner.with_allowlist(extra_allowlist)
        if inner is self.inner:
            return self
        clone = copy.copy(self)
        clone.inner = inner
        clone.serde = inner.serde
        return clone

    # -- recording ------------------------------------------------------------
    def _record(self, memory_id: str, content: str) -> None:
        recorded = _bounded(content, self._blackbox.max_content_bytes)
        if self._blackbox.ledger.last_write_hash(self._namespace, memory_id) == hash_content(
            recorded
        ):
            return  # unchanged since it was last recorded
        self._blackbox.record_write(
            recorded,
            self._source or _thread_source(memory_id),
            namespace=self._namespace,
            memory_id=memory_id,
            memory_type=MemoryType.episodic,
            scan=self._new_text(content),
        )

    def _new_text(self, content: str) -> str:
        """The memory text in ``content`` this thread has not had scanned yet.

        Every checkpoint repeats the whole conversation, so scanning full content
        would re-report one injected message on every later step. Each string is
        scanned once per thread instead, from the full content (never the bounded
        copy), so a long history is still scanned in full.
        """
        found = _memory_values(content)
        if found is None:
            return ""
        thread_id, values = found
        fresh: list[str] = []
        with self._scanned_lock:
            seen = self._scanned.setdefault(thread_id, set())
            if len(seen) > _SCANNED_CAP:
                seen.clear()
            for text in _strings(values):
                if hash(text) not in seen:
                    seen.add(hash(text))
                    fresh.append(text)
        return "\n".join(fresh)

    def _record_tuple(self, tup: CheckpointTuple | None, config: RunnableConfig) -> None:
        if tup is None:
            raise CheckpointIntegrityError(f"checkpoint not readable right after saving: {config}")
        self._record(*_checkpoint_content(tup, self.serde))
        for memory_id, content in _writes_contents(tup, self.serde).items():
            self._record(memory_id, content)

    def _record_task(self, tup: CheckpointTuple | None, task_id: str) -> None:
        if tup is None:
            # LangGraph saves writes and their checkpoint concurrently; when the
            # writes land first, put()'s read-back of the checkpoint records them.
            return
        thread_id, ns, checkpoint_id = _ids(tup.config)
        memory_id = writes_memory_id(thread_id, ns, checkpoint_id, str(task_id))
        content = _writes_contents(tup, self.serde).get(memory_id)
        if content is not None:
            self._record(memory_id, content)

    def _on_read(self, tup: CheckpointTuple) -> None:
        if self._verify_on_read:
            ledger = self._blackbox.ledger
            limit = self._blackbox.max_content_bytes
            for memory_id, digest in _tuple_hashes(tup, self.serde, limit).items():
                recorded = ledger.last_write_hash(self._namespace, memory_id)
                if recorded != digest:
                    why = "never recorded" if recorded is None else "differs from the ledger"
                    raise CheckpointIntegrityError(f"refusing to serve {memory_id}: {why}")
        memory_id, _ = _checkpoint_content(tup, self.serde)
        found = self._blackbox.ledger.last_write(self._namespace, memory_id)
        self._blackbox.record_retrieval(
            memory_id, [found[0]] if found else [], namespace=self._namespace
        )

    def _tombstone_removed(self, before: dict[str, str], after: dict[str, str], op: str) -> None:
        # Only what was present a moment ago and is recorded live gets a tombstone;
        # anything already missing stays missing, so the audit still reports it.
        live = _ledger_entries(self._blackbox.ledger, self._namespace, None)
        for memory_id in sorted(before.keys() - after.keys()):
            entry = live.get(memory_id)
            if entry is not None and not entry.deleted and entry.content_hash == before[memory_id]:
                self._record(memory_id, _tombstone(memory_id, op))

    def _guard_copy(self, report: CheckpointAuditReport, source_thread_id: str) -> None:
        if not report.ok:
            first = report.issues[0]
            raise CheckpointIntegrityError(
                f"refusing to copy thread {source_thread_id!r}: {first.kind} {first.memory_id}"
            )

    # -- sync API -------------------------------------------------------------
    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        tup = self.inner.get_tuple(config)
        if tup is not None:
            self._on_read(tup)
        return tup

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        return self.inner.list(config, filter=filter, before=before, limit=limit)

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        saved = self.inner.put(config, checkpoint, metadata, new_versions)
        self._record_tuple(self.inner.get_tuple(saved), saved)
        return saved

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        self.inner.put_writes(config, writes, task_id, task_path)
        self._record_task(self.inner.get_tuple(config), task_id)

    def _deleting(
        self, op: str, thread_ids: Sequence[str] | None, call: Callable[[], None]
    ) -> None:
        limit = self._blackbox.max_content_bytes
        before = _present(self.inner, thread_ids, limit)
        call()
        self._tombstone_removed(before, _present(self.inner, thread_ids, limit), op)

    def delete_thread(self, thread_id: str) -> None:
        self._deleting("delete_thread", [thread_id], lambda: self.inner.delete_thread(thread_id))

    def delete_for_runs(self, run_ids: Sequence[str]) -> None:
        # Runs don't name their threads, so this diffs the whole store.
        self._deleting("delete_for_runs", None, lambda: self.inner.delete_for_runs(run_ids))

    def prune(self, thread_ids: Sequence[str], *, strategy: str = "keep_latest") -> None:
        self._deleting(
            f"prune:{strategy}", thread_ids, lambda: self.inner.prune(thread_ids, strategy=strategy)
        )

    def copy_thread(self, source_thread_id: str, target_thread_id: str) -> None:
        self._guard_copy(self.audit(thread_ids=[source_thread_id]), source_thread_id)
        self.inner.copy_thread(source_thread_id, target_thread_id)
        for tup in self.inner.list({"configurable": {"thread_id": target_thread_id}}):
            self._record_tuple(tup, tup.config)

    def get_delta_channel_history(
        self, *, config: RunnableConfig, channels: Sequence[str]
    ) -> Mapping[str, DeltaChannelHistory]:
        return self.inner.get_delta_channel_history(config=config, channels=channels)

    def audit(
        self, *, thread_ids: Sequence[str] | None = None, verify_ledger: bool = True
    ) -> CheckpointAuditReport:
        """Reconcile the wrapped store with the ledger; see ``audit_checkpoints``."""
        return audit_checkpoints(
            self.inner,
            self._blackbox,
            namespace=self._namespace,
            thread_ids=thread_ids,
            verify_ledger=verify_ledger,
        )

    # -- async API ------------------------------------------------------------
    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        tup = await self.inner.aget_tuple(config)
        if tup is not None:
            self._on_read(tup)
        return tup

    def alist(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[CheckpointTuple]:
        return self.inner.alist(config, filter=filter, before=before, limit=limit)

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        saved = await self.inner.aput(config, checkpoint, metadata, new_versions)
        self._record_tuple(await self.inner.aget_tuple(saved), saved)
        return saved

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        await self.inner.aput_writes(config, writes, task_id, task_path)
        self._record_task(await self.inner.aget_tuple(config), task_id)

    async def _adeleting(
        self, op: str, thread_ids: Sequence[str] | None, call: Callable[[], Awaitable[None]]
    ) -> None:
        limit = self._blackbox.max_content_bytes
        before = await _apresent(self.inner, thread_ids, limit)
        await call()
        self._tombstone_removed(before, await _apresent(self.inner, thread_ids, limit), op)

    async def adelete_thread(self, thread_id: str) -> None:
        await self._adeleting(
            "delete_thread", [thread_id], lambda: self.inner.adelete_thread(thread_id)
        )

    async def adelete_for_runs(self, run_ids: Sequence[str]) -> None:
        await self._adeleting("delete_for_runs", None, lambda: self.inner.adelete_for_runs(run_ids))

    async def aprune(self, thread_ids: Sequence[str], *, strategy: str = "keep_latest") -> None:
        await self._adeleting(
            f"prune:{strategy}",
            thread_ids,
            lambda: self.inner.aprune(thread_ids, strategy=strategy),
        )

    async def acopy_thread(self, source_thread_id: str, target_thread_id: str) -> None:
        report = await self.aaudit(thread_ids=[source_thread_id])
        self._guard_copy(report, source_thread_id)
        await self.inner.acopy_thread(source_thread_id, target_thread_id)
        async for tup in self.inner.alist({"configurable": {"thread_id": target_thread_id}}):
            self._record_tuple(tup, tup.config)

    async def aget_delta_channel_history(
        self, *, config: RunnableConfig, channels: Sequence[str]
    ) -> Mapping[str, DeltaChannelHistory]:
        return await self.inner.aget_delta_channel_history(config=config, channels=channels)

    async def aaudit(
        self, *, thread_ids: Sequence[str] | None = None, verify_ledger: bool = True
    ) -> CheckpointAuditReport:
        """Async ``audit``."""
        return await aaudit_checkpoints(
            self.inner,
            self._blackbox,
            namespace=self._namespace,
            thread_ids=thread_ids,
            verify_ledger=verify_ledger,
        )
