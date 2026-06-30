"""MCP gateway: a provenance-logging proxy for memory MCP servers.

The agent points at the gateway instead of the real memory MCP server. For every
``tools/call`` the gateway forwards the request upstream unchanged and returns the
upstream response byte-identical, while logging memory writes and reads with full
provenance. It is backend-agnostic: any MCP memory server is covered by declaring
which tool names are writes vs reads and how to read their arguments/results
(reusing the same WriteMap/ReadMap extractors as the library wrapper).

The core here is transport-agnostic and fully testable offline. Binding it to a
real stdio/SSE MCP transport is a thin layer added when the ``mcp`` extra is present.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memory_blackbox.capture.wrapper import CallCtx

if TYPE_CHECKING:
    from collections.abc import Callable

    from memory_blackbox.capture.engine import Forensics
    from memory_blackbox.capture.wrapper import ReadMap, WriteMap
    from memory_blackbox.model.records import Source


class McpGateway:
    """Forwards MCP tool calls upstream, logging memory reads/writes."""

    def __init__(
        self,
        forensics: Forensics,
        forward: Callable[[str, dict[str, Any]], Any],
        *,
        namespace: str,
        default_source: Source,
        write_tools: dict[str, WriteMap],
        read_tools: dict[str, ReadMap],
    ) -> None:
        self._forensics = forensics
        self._forward = forward
        self._namespace = namespace
        self._default_source = default_source
        self._write_tools = write_tools
        self._read_tools = read_tools

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Forward a tools/call upstream unchanged and log provenance if relevant."""
        result = self._forward(name, arguments)
        ctx = CallCtx(args=(), kwargs=arguments, result=result)
        if name in self._write_tools:
            write_spec = self._write_tools[name]
            self._forensics.record_write(
                write_spec.content(ctx),
                self._default_source,
                namespace=self._namespace,
                memory_id=write_spec.memory_id(ctx),
            )
        elif name in self._read_tools:
            read_spec = self._read_tools[name]
            self._forensics.record_retrieval(
                read_spec.query(ctx),
                list(read_spec.returned(ctx)),
                list(read_spec.scores(ctx)),
                namespace=self._namespace,
            )
        return result
