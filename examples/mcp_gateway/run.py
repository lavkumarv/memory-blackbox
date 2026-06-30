#!/usr/bin/env python3
"""MCP gateway example.

The gateway sits between an agent and a memory MCP server. It forwards every
``tools/call`` upstream **unchanged** and returns the upstream response
byte-identical, while logging memory writes and reads with full provenance.

Run it:

    python examples/mcp_gateway/run.py

Here the upstream is a tiny in-process fake; in production `forward` would call
your real MCP memory server.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from memory_blackbox.capture.engine import Forensics
from memory_blackbox.capture.gateway import McpGateway
from memory_blackbox.capture.wrapper import ReadMap, WriteMap
from memory_blackbox.crypto import keys
from memory_blackbox.model.records import Source, SourceType, TrustLevel


class FakeMcpMemoryServer:
    """Stands in for a real MCP memory server's tools/call handler."""

    def __init__(self) -> None:
        self._n = 0

    def call(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "create_memory":
            self._n += 1
            return {"id": f"node-{self._n}", "status": "ok"}
        if name == "search_memory":
            return {"matches": [{"id": "node-1", "score": 0.82}]}
        return {"status": "ok"}


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        forensics = Forensics.open(Path(tmp) / "gateway.db", keys.generate(), detectors=[])
        upstream = FakeMcpMemoryServer()

        gateway = McpGateway(
            forensics,
            upstream.call,  # forward(tool_name, arguments) -> result
            namespace="agent",
            default_source=Source(
                source_id="mcp-memory",
                source_type=SourceType.tool_output,
                trust_level=TrustLevel.semi_trusted,
                locator="mcp://memory-server",
            ),
            # Declare which tools are writes vs reads, and how to read their I/O.
            write_tools={
                "create_memory": WriteMap(
                    content=lambda c: str(c.kwargs.get("content", "")),
                    memory_id=lambda c: c.result.get("id"),
                ),
            },
            read_tools={
                "search_memory": ReadMap(
                    query=lambda c: str(c.kwargs.get("query", "")),
                    returned=lambda c: [m["id"] for m in c.result.get("matches", [])],
                ),
            },
        )

        # The agent's tool calls flow through the gateway.
        created = gateway.call_tool("create_memory", {"content": "the capital of France is Paris"})
        found = gateway.call_tool("search_memory", {"query": "capital of France"})

    print("Upstream responses are forwarded unchanged:")
    print("  create_memory ->", created)
    print("  search_memory ->", found)
    print(
        f"\nProvenance captured: {forensics.ledger.count()} ledger record(s) "
        "(1 write + 1 retrieval), each signed and chained."
    )


if __name__ == "__main__":
    main()
