"""Template: add an adapter for a new memory backend.

An adapter declares how to capture a backend: which methods are writes vs reads,
and how to pull content/ids/query/results out of each call (the WriteMap/ReadMap
extractors the generic wrapper applies). No SDK import is needed in the adapter — it
only describes call shapes, so it works against the real client or a fake.

Run it:  python examples/extending/adapter_template.py
"""

from __future__ import annotations

from memory_blackbox.adapters.base import Adapter
from memory_blackbox.capture.wrapper import ReadMap, WriteMap


def my_backend_adapter() -> Adapter:
    """Map a backend with ``store(text) -> id`` and ``lookup(q) -> [ids]``."""
    return Adapter(
        backend_name="my_backend",
        write_methods={
            "store": WriteMap(
                content=lambda c: str(c.args[0]),  # first positional arg is the content
                memory_id=lambda c: c.result,  # the method returns the new id
            ),
        },
        read_methods={
            "lookup": ReadMap(
                query=lambda c: str(c.args[0]),
                returned=lambda c: list(c.result),
            ),
        },
    )


if __name__ == "__main__":
    import tempfile
    from pathlib import Path

    from memory_blackbox.capture.engine import MemoryBlackbox
    from memory_blackbox.crypto import keys
    from memory_blackbox.model.records import Source, SourceType

    class MyBackend:
        def __init__(self) -> None:
            self._store: dict[str, str] = {}

        def store(self, text: str) -> str:
            mid = f"id-{len(self._store) + 1}"
            self._store[mid] = text
            return mid

        def lookup(self, query: str) -> list[str]:
            return list(self._store)

    with tempfile.TemporaryDirectory() as tmp:
        blackbox = MemoryBlackbox.open(Path(tmp) / "l.db", keys.generate(), detectors=[])
        client = blackbox.wrap_adapter(
            MyBackend(),
            my_backend_adapter(),
            namespace="demo",
            default_source=Source(source_type=SourceType.tool_output),
        )
        client.store("remember this")  # captured + forwarded
        client.lookup("remember")  # captured + forwarded
        print("ledger records:", blackbox.ledger.count())
