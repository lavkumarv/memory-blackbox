"""Time-sortable UUIDv7 generation (RFC 9562).

Record ids are uuid7 so they sort chronologically, which keeps the ledger and the
DAG naturally ordered. Generation is monotonic within a process: ids minted in the
same millisecond still strictly increase, so two records never collide or sort
ambiguously even under a burst.

Vendored (≈40 lines) rather than taking a dependency, per the minimal-deps rule.
"""

from __future__ import annotations

import os
import threading
import time
from uuid import UUID

_VERSION = 0x7
_VARIANT = 0b10
_RAND_BITS = 74  # 12 bits rand_a + 62 bits rand_b
_RAND_MASK = (1 << _RAND_BITS) - 1
_RAND_B_MASK = (1 << 62) - 1

_lock = threading.Lock()
_last_ms = -1
_last_rand = 0


def _compose(ms: int, rand: int) -> UUID:
    rand_a = (rand >> 62) & 0xFFF
    rand_b = rand & _RAND_B_MASK
    value = (ms & 0xFFFFFFFFFFFF) << 80
    value |= _VERSION << 76
    value |= rand_a << 64
    value |= _VARIANT << 62
    value |= rand_b
    return UUID(int=value)


def uuid7() -> UUID:
    """Return a new time-sortable, process-monotonic UUIDv7."""
    global _last_ms, _last_rand
    with _lock:
        ms = time.time_ns() // 1_000_000
        if ms <= _last_ms:
            # Same or backward clock: keep the timestamp and bump the random field.
            ms = _last_ms
            rand = _last_rand + 1
            if rand > _RAND_MASK:  # overflow the 74-bit field: advance to the next ms
                ms += 1
                rand = int.from_bytes(os.urandom(10), "big") >> (80 - _RAND_BITS)
        else:
            rand = int.from_bytes(os.urandom(10), "big") >> (80 - _RAND_BITS)
        _last_ms = ms
        _last_rand = rand
        return _compose(ms, rand)


def uuid7_str() -> str:
    """Return a new UUIDv7 as a string."""
    return str(uuid7())
