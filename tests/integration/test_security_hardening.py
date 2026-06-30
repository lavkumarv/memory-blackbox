"""Tests for security-hardening guards added after the audit."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from memory_blackbox.capture.engine import ContentTooLargeError, Forensics
from memory_blackbox.crypto import keys
from memory_blackbox.ledger.store import LedgerStore
from memory_blackbox.model.records import Source, SourceType


def _src() -> Source:
    return Source(source_type=SourceType.user_input)


def test_content_size_cap_rejects_oversized_write(tmp_path: Path) -> None:
    eng = Forensics.open(tmp_path / "l.db", keys.generate(), detectors=[], max_content_bytes=1024)
    eng.record_write("x" * 1024, _src())  # exactly at the limit is fine
    with pytest.raises(ContentTooLargeError):
        eng.record_write("x" * 1025, _src())


def test_default_content_cap_is_generous(tmp_path: Path) -> None:
    eng = Forensics.open(tmp_path / "l.db", keys.generate(), detectors=[])
    # A normal-sized memory is never rejected.
    rec = eng.record_write("a perfectly normal memory" * 100, _src())
    assert rec.record_id is not None


def test_invalid_synchronous_mode_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="synchronous"):
        LedgerStore(tmp_path / "l.db", keys.generate(), synchronous="OFF; DROP TABLE ledger")


def test_valid_synchronous_modes_accepted(tmp_path: Path) -> None:
    for mode in ("off", "NORMAL", "full"):
        store = LedgerStore(tmp_path / f"{mode}.db", keys.generate(), synchronous=mode)
        store.close()


def test_ledger_file_is_owner_only(tmp_path: Path) -> None:
    db = tmp_path / "l.db"
    LedgerStore(db, keys.generate()).close()
    mode = stat.S_IMODE(os.stat(db).st_mode)
    assert mode == 0o600


def test_memory_md_skips_oversized_file(tmp_path: Path) -> None:
    from memory_blackbox.adapters.memory_md import MemoryMdAdapter

    eng = Forensics.open(tmp_path / "l.db", keys.generate(), detectors=[], max_content_bytes=64)
    big = tmp_path / "MEMORY.md"
    big.write_text("x" * 4096)
    adapter = MemoryMdAdapter(eng, tmp_path)
    assert adapter.scan() == []  # too large -> skipped, not OOM
    assert eng.ledger.count() == 0
