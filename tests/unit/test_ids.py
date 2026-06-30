"""Tests for uuid7 generation (spec §15.1 supporting)."""

from __future__ import annotations

from memory_blackbox.model.ids import uuid7, uuid7_str


def test_uuid7_version_and_variant() -> None:
    u = uuid7()
    assert u.version == 7
    assert (u.int >> 62) & 0b11 == 0b10  # RFC 4122/9562 variant


def test_uuid7_monotonic_within_process() -> None:
    values = [uuid7() for _ in range(10_000)]
    assert values == sorted(values)
    assert len(set(values)) == len(values)  # all unique


def test_uuid7_str_round_trips() -> None:
    from uuid import UUID

    s = uuid7_str()
    assert str(UUID(s)) == s
