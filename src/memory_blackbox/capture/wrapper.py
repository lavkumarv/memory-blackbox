"""Generic backend wrapper.

A `WrappedClient` proxies a memory backend: it forwards every call to the real
client, and for methods declared in ``write_methods`` / ``read_methods`` it also
records a provenance write or retrieval. An adapter (M9) supplies the mappings;
each mapping is a set of small extractors that pull the content, ids, query, and
scores out of the call's arguments and result. The forwarded return value is the
backend's own, unchanged.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from memory_blackbox.capture.engine import Forensics
    from memory_blackbox.model.records import Source


@dataclass(frozen=True, slots=True)
class CallCtx:
    """The arguments and result of a single intercepted backend call."""

    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    result: Any


@dataclass(frozen=True, slots=True)
class WriteMap:
    """How to extract a write from an intercepted call."""

    content: Callable[[CallCtx], str]
    memory_id: Callable[[CallCtx], str | None] = lambda _ctx: None


@dataclass(frozen=True, slots=True)
class ReadMap:
    """How to extract a retrieval from an intercepted call."""

    query: Callable[[CallCtx], str]
    returned: Callable[[CallCtx], Sequence[str]]
    scores: Callable[[CallCtx], Sequence[float]] = field(default=lambda _ctx: ())


class WrappedClient:
    """A capture proxy around a memory backend client."""

    def __init__(
        self,
        forensics: Forensics,
        client: object,
        *,
        namespace: str,
        default_source: Source,
        write_methods: dict[str, WriteMap],
        read_methods: dict[str, ReadMap],
    ) -> None:
        self._forensics = forensics
        self._client = client
        self._namespace = namespace
        self._default_source = default_source
        self._write_methods = write_methods
        self._read_methods = read_methods

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._client, name)
        if name in self._write_methods:
            return self._wrap_write(name, attr, self._write_methods[name])
        if name in self._read_methods:
            return self._wrap_read(name, attr, self._read_methods[name])
        return attr

    def _wrap_write(
        self, name: str, method: Callable[..., Any], spec: WriteMap
    ) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = method(*args, **kwargs)
            ctx = CallCtx(args=args, kwargs=kwargs, result=result)
            self._forensics.record_write(
                spec.content(ctx),
                self._default_source,
                namespace=self._namespace,
                memory_id=spec.memory_id(ctx),
            )
            return result

        return wrapper

    def _wrap_read(
        self, name: str, method: Callable[..., Any], spec: ReadMap
    ) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = method(*args, **kwargs)
            ctx = CallCtx(args=args, kwargs=kwargs, result=result)
            self._forensics.record_retrieval(
                spec.query(ctx),
                list(spec.returned(ctx)),
                list(spec.scores(ctx)),
                namespace=self._namespace,
            )
            return result

        return wrapper
