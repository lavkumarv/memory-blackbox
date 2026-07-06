"""Tests for the MCP gateway (spec §15.10)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from memory_blackbox.capture.engine import MemoryBlackbox
from memory_blackbox.capture.gateway import McpGateway
from memory_blackbox.capture.wrapper import CallCtx, ReadMap, WriteMap
from memory_blackbox.crypto import keys
from memory_blackbox.model.records import Source, SourceType


class FakeMcpMemoryServer:
    """A minimal stand-in for an MCP memory server's tools/call handler."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._n = 0

    def call(self, name: str, arguments: dict[str, Any]) -> Any:
        self.calls.append((name, arguments))
        if name == "create_memory":
            self._n += 1
            return {"id": f"node-{self._n}", "status": "ok"}
        if name == "search_memory":
            return {"matches": [{"id": "node-1", "score": 0.8}]}
        return {"status": "ok"}


@pytest.fixture
def blackbox(tmp_path: Path) -> MemoryBlackbox:
    return MemoryBlackbox.open(tmp_path / "l.db", keys.generate(), detectors=[])


def _gateway(blackbox: MemoryBlackbox, server: FakeMcpMemoryServer) -> McpGateway:
    write_tools = {
        "create_memory": WriteMap(
            content=lambda c: str(c.kwargs.get("content", "")),
            memory_id=lambda c: c.result.get("id") if isinstance(c.result, dict) else None,
        )
    }
    read_tools = {
        "search_memory": ReadMap(
            query=lambda c: str(c.kwargs.get("query", "")),
            returned=lambda c: [m["id"] for m in c.result.get("matches", [])],
        )
    }
    return McpGateway(
        blackbox,
        server.call,
        namespace="t",
        default_source=Source(
            source_id="mcp", source_type=SourceType.tool_output, locator="mcp://"
        ),
        write_tools=write_tools,
        read_tools=read_tools,
    )


def test_write_tool_call_is_logged_and_forwarded_unchanged(blackbox: MemoryBlackbox) -> None:
    server = FakeMcpMemoryServer()
    gateway = _gateway(blackbox, server)

    response = gateway.call_tool("create_memory", {"content": "the capital of France is Paris"})

    # Forwarded byte-identical: the gateway returns the upstream object as-is.
    assert response == {"id": "node-1", "status": "ok"}
    assert server.calls == [("create_memory", {"content": "the capital of France is Paris"})]
    # And a provenance write was logged with the round-tripped memory id.
    write = next(r for r in blackbox.ledger.rows() if r["kind"] == "write")
    assert '"memory_id":"node-1"' in write["payload_json"]


def test_read_tool_call_is_logged_and_forwarded_unchanged(blackbox: MemoryBlackbox) -> None:
    server = FakeMcpMemoryServer()
    gateway = _gateway(blackbox, server)
    gateway.call_tool("create_memory", {"content": "Paris"})

    response = gateway.call_tool("search_memory", {"query": "capital of France"})

    assert response == {"matches": [{"id": "node-1", "score": 0.8}]}
    retrieval = next(r for r in blackbox.ledger.rows() if r["kind"] == "retrieval")
    assert "node-1" in retrieval["payload_json"]


def test_unmapped_tool_is_forwarded_without_logging(blackbox: MemoryBlackbox) -> None:
    server = FakeMcpMemoryServer()
    gateway = _gateway(blackbox, server)
    response = gateway.call_tool("ping", {})
    assert response == {"status": "ok"}
    assert blackbox.ledger.count() == 0


def test_response_object_identity_preserved(blackbox: MemoryBlackbox) -> None:
    sentinel = {"id": "x", "payload": object()}
    gateway = McpGateway(
        blackbox,
        lambda name, args: sentinel,
        namespace="t",
        default_source=Source(source_id="mcp", source_type=SourceType.tool_output),
        write_tools={},
        read_tools={},
    )
    assert gateway.call_tool("anything", {}) is sentinel


def test_callctx_used_by_gateway_specs() -> None:
    # Guard: the gateway feeds arguments via kwargs in CallCtx.
    ctx = CallCtx(args=(), kwargs={"content": "hi"}, result={"id": "1"})
    assert ctx.kwargs["content"] == "hi"
