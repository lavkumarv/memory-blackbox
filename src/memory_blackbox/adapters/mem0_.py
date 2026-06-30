"""Mem0 adapter.

Intercepts ``Memory.add`` (write) and ``Memory.search`` / ``Memory.get_all``
(read). Mem0 returns rich metadata, so we round-trip our ``record_id`` through its
result. The mapping is SDK-free; it only describes how to read the call shapes, so
it works against the real ``mem0ai`` client or a compatible fake.
"""

from __future__ import annotations

from typing import Any

from memory_blackbox.adapters.base import Adapter
from memory_blackbox.capture.wrapper import CallCtx, ReadMap, WriteMap


def _add_content(ctx: CallCtx) -> str:
    # Memory.add(messages, ...): messages may be a string or a list of role/content dicts.
    messages = ctx.args[0] if ctx.args else ctx.kwargs.get("messages", "")
    if isinstance(messages, str):
        return messages
    if isinstance(messages, list):
        return "\n".join(m.get("content", "") if isinstance(m, dict) else str(m) for m in messages)
    return str(messages)


def _add_memory_id(ctx: CallCtx) -> str | None:
    result = ctx.result
    if isinstance(result, dict):
        results = result.get("results") or result.get("memories")
        if isinstance(results, list) and results and isinstance(results[0], dict):
            mid = results[0].get("id")
            return str(mid) if mid is not None else None
        mid = result.get("id")
        return str(mid) if mid is not None else None
    return None


def _search_returned(ctx: CallCtx) -> list[str]:
    result = ctx.result
    items: list[Any] = []
    if isinstance(result, dict):
        items = result.get("results") or result.get("memories") or []
    elif isinstance(result, list):
        items = result
    return [str(i.get("id")) for i in items if isinstance(i, dict) and i.get("id") is not None]


def _search_scores(ctx: CallCtx) -> list[float]:
    result = ctx.result
    items: list[Any] = []
    if isinstance(result, dict):
        items = result.get("results") or result.get("memories") or []
    elif isinstance(result, list):
        items = result
    return [float(i["score"]) for i in items if isinstance(i, dict) and "score" in i]


def _search_query(ctx: CallCtx) -> str:
    return str(ctx.args[0] if ctx.args else ctx.kwargs.get("query", ""))


def mem0_adapter() -> Adapter:
    """Return the Mem0 capture adapter."""
    read = ReadMap(query=_search_query, returned=_search_returned, scores=_search_scores)
    return Adapter(
        backend_name="mem0",
        write_methods={"add": WriteMap(content=_add_content, memory_id=_add_memory_id)},
        read_methods={"search": read, "get_all": read},
    )
