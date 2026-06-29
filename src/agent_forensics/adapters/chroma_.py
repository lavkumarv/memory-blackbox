"""Chroma adapter.

Intercepts ``collection.add`` (write) and ``collection.query`` (read). Chroma
takes parallel lists (documents/ids) and returns nested lists keyed by query.
The mapping is SDK-free and works against a real ``chromadb`` collection or a fake.
"""

from __future__ import annotations

from typing import Any

from agent_forensics.adapters.base import Adapter
from agent_forensics.capture.wrapper import CallCtx, ReadMap, WriteMap


def _add_content(ctx: CallCtx) -> str:
    documents = ctx.kwargs.get("documents")
    if documents is None and ctx.args:
        documents = ctx.args[0]
    if isinstance(documents, list):
        return "\n".join(str(d) for d in documents)
    return str(documents or "")


def _add_memory_id(ctx: CallCtx) -> str | None:
    ids = ctx.kwargs.get("ids")
    if isinstance(ids, list) and ids:
        return str(ids[0])
    if isinstance(ids, str):
        return ids
    return None


def _query_text(ctx: CallCtx) -> str:
    texts = ctx.kwargs.get("query_texts")
    if isinstance(texts, list) and texts:
        return str(texts[0])
    return str(texts or "")


def _flatten_first(value: Any) -> list[Any]:
    # Chroma returns {"ids": [[...]], "distances": [[...]]} (one inner list per query).
    if isinstance(value, list) and value and isinstance(value[0], list):
        return list(value[0])
    if isinstance(value, list):
        return value
    return []


def _query_returned(ctx: CallCtx) -> list[str]:
    result = ctx.result
    if isinstance(result, dict):
        return [str(i) for i in _flatten_first(result.get("ids"))]
    return []


def _query_scores(ctx: CallCtx) -> list[float]:
    result = ctx.result
    if isinstance(result, dict):
        return [float(d) for d in _flatten_first(result.get("distances"))]
    return []


def chroma_adapter() -> Adapter:
    """Return the Chroma capture adapter."""
    return Adapter(
        backend_name="chroma",
        write_methods={"add": WriteMap(content=_add_content, memory_id=_add_memory_id)},
        read_methods={
            "query": ReadMap(query=_query_text, returned=_query_returned, scores=_query_scores)
        },
    )
