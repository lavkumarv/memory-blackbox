# MCP gateway example

A backend-agnostic proxy: point your agent at the gateway instead of the real
memory MCP server. Every `tools/call` is forwarded upstream **unchanged** (the
response is returned byte-identical), while memory writes and reads are logged
with signed provenance.

```bash
python examples/mcp_gateway/run.py
```

You declare which tool names are writes vs reads and how to read their
arguments/results (`WriteMap`/`ReadMap`); the gateway handles the rest. The core
is transport-agnostic — `forward(tool_name, arguments)` is the single seam to your
real MCP server (stdio/SSE).
