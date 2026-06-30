"""Letta adapter.

Intercepts archival-memory insertion (write) and archival/recall search (read).
Letta's client exposes ``insert_archival_memory`` / ``get_archival_memory`` style
methods; the mapping is SDK-free and works against the real client or a fake.
"""

from __future__ import annotations

from typing import Any

from memory_blackbox.adapters.base import Adapter
from memory_blackbox.capture.wrapper import CallCtx, ReadMap, WriteMap


def _insert_content(ctx: CallCtx) -> str:
    if "memory" in ctx.kwargs:
        return str(ctx.kwargs["memory"])
    # insert_archival_memory(agent_id, memory) -> content is the last positional arg.
    return str(ctx.args[-1]) if ctx.args else ""


def _insert_memory_id(ctx: CallCtx) -> str | None:
    result = ctx.result
    if isinstance(result, dict) and result.get("id") is not None:
        return str(result["id"])
    if isinstance(result, list) and result and isinstance(result[0], dict):
        mid = result[0].get("id")
        return str(mid) if mid is not None else None
    return None


def _search_query(ctx: CallCtx) -> str:
    if "query" in ctx.kwargs:
        return str(ctx.kwargs["query"])
    return str(ctx.args[-1]) if ctx.args else ""


def _search_returned(ctx: CallCtx) -> list[str]:
    result = ctx.result
    items: list[Any] = result if isinstance(result, list) else []
    return [str(i.get("id")) for i in items if isinstance(i, dict) and i.get("id") is not None]


def letta_adapter() -> Adapter:
    """Return the Letta capture adapter."""
    read = ReadMap(query=_search_query, returned=_search_returned)
    return Adapter(
        backend_name="letta",
        write_methods={
            "insert_archival_memory": WriteMap(content=_insert_content, memory_id=_insert_memory_id)
        },
        read_methods={"get_archival_memory": read, "search_archival_memory": read},
    )
