"""Rekor backend against an in-process fake transparency log.

The fake implements the slice of Rekor's v1 API this backend uses, and implements
it *honestly*: entries are canonicalized the way Rekor canonicalizes a ``rekord``
(payload replaced by its SHA-256), and inclusion proofs are generated from a real
RFC 6962 tree. That is what makes these tests meaningful -- ``verify_receipt``
recomputes the leaf hash and walks the proof, so a fake that returned made-up
proofs would fail exactly as a hostile log would.

What a fake cannot cover is whether the live service accepts this entry shape.
That is a live smoke test against a real log, not a unit test; see
``docs/anchoring.md``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from memory_blackbox.anchor.base import AnchorError, ledger_id
from memory_blackbox.anchor.rekor import RekorAnchor
from memory_blackbox.anchor.store import AnchorStore
from memory_blackbox.anchor.verify import DivergenceKind, anchor_now, verify_anchors
from memory_blackbox.crypto import keys
from memory_blackbox.ledger.store import LedgerStore
from memory_blackbox.model.records import ProvenanceRecord, Source, SourceType

pytestmark = pytest.mark.integration


# --- a minimal, honest RFC 6962 log ----------------------------------------
def _leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _mth(entries: list[bytes]) -> bytes:
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return _leaf_hash(entries[0])
    split = 1 << (len(entries) - 1).bit_length() - 1
    return _node_hash(_mth(entries[:split]), _mth(entries[split:]))


def _path(index: int, entries: list[bytes]) -> list[bytes]:
    if len(entries) <= 1:
        return []
    split = 1 << (len(entries) - 1).bit_length() - 1
    if index < split:
        return [*_path(index, entries[:split]), _mth(entries[split:])]
    return [*_path(index - split, entries[split:]), _mth(entries[:split])]


class FakeRekorLog:
    """Append-only store of canonicalized rekord entries, with real proofs."""

    def __init__(self) -> None:
        self.entries: list[bytes] = []
        self.uuids: list[str] = []
        self.public_keys: list[str] = []
        self.reject_next = False

    def add(self, entry: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        spec = entry["spec"]
        payload = base64.b64decode(spec["data"]["content"])
        # Rekor persists the payload's hash, not the payload -- reproduce that,
        # because the backend's whole matching strategy depends on it.
        canonical = {
            "apiVersion": entry["apiVersion"],
            "kind": entry["kind"],
            "spec": {
                "data": {
                    "hash": {"algorithm": "sha256", "value": hashlib.sha256(payload).hexdigest()}
                },
                "signature": spec["signature"],
            },
        }
        entry_bytes = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        self.entries.append(entry_bytes)
        self.public_keys.append(spec["signature"]["publicKey"]["content"])
        uuid = hashlib.sha256(entry_bytes).hexdigest()
        self.uuids.append(uuid)
        return uuid, self.entry_response(len(self.entries) - 1)

    def entry_response(self, index: int) -> dict[str, Any]:
        entry_bytes = self.entries[index]
        size = len(self.entries)
        root = _mth(self.entries)
        checkpoint = "\n".join(
            ["fake-rekor", str(size), base64.b64encode(root).decode("ascii"), ""]
        )
        return {
            "body": base64.b64encode(entry_bytes).decode("ascii"),
            "integratedTime": 1_700_000_000 + index,
            "logID": "fake-log",
            "logIndex": index,
            "verification": {
                "inclusionProof": {
                    "checkpoint": checkpoint,
                    "hashes": [h.hex() for h in _path(index, self.entries)],
                    "logIndex": index,
                    "rootHash": root.hex(),
                    "treeSize": size,
                },
                "signedEntryTimestamp": "",
            },
        }

    def find_by_public_key(self, content: str) -> list[str]:
        return [u for u, k in zip(self.uuids, self.public_keys, strict=True) if k == content]

    def find(self, uuid: str) -> dict[str, Any] | None:
        if uuid not in self.uuids:
            return None
        return self.entry_response(self.uuids.index(uuid))


def _make_handler(log: FakeRekorLog) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:  # keep pytest output clean
            pass

        def _reply(self, status: int, payload: Any) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # BaseHTTPRequestHandler dispatches on this name
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/api/v1/log/entries":
                if log.reject_next:
                    log.reject_next = False
                    self._reply(409, {"code": 409, "message": "entry already exists"})
                    return
                uuid, entry = log.add(payload)
                self._reply(201, {uuid: entry})
            elif self.path == "/api/v1/index/retrieve":
                key = (payload.get("publicKey") or {}).get("content", "")
                self._reply(200, log.find_by_public_key(key))
            else:
                self._reply(404, {"code": 404, "message": "not found"})

        def do_GET(self) -> None:  # BaseHTTPRequestHandler dispatches on this name
            prefix = "/api/v1/log/entries/"
            if self.path.startswith(prefix):
                entry = log.find(self.path[len(prefix) :])
                if entry is None:
                    self._reply(404, {"code": 404, "message": "not found"})
                    return
                uuid = self.path[len(prefix) :]
                self._reply(200, {uuid: entry})
            else:
                self._reply(404, {"code": 404, "message": "not found"})

    return Handler


@pytest.fixture
def fake_log() -> FakeRekorLog:
    return FakeRekorLog()


@pytest.fixture
def rekor(fake_log: FakeRekorLog) -> Any:
    server = HTTPServer(("127.0.0.1", 0), _make_handler(fake_log))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield RekorAnchor(f"http://127.0.0.1:{server.server_port}", timeout=10.0)
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def signer() -> keys.KeyPair:
    return keys.generate()


@pytest.fixture
def store(tmp_path: Path, signer: keys.KeyPair) -> LedgerStore:
    return LedgerStore(tmp_path / "ledger.db", signer, checkpoint_every=0)


def _fill(store: LedgerStore, count: int, prefix: str = "e") -> None:
    for i in range(count):
        store.append(
            ProvenanceRecord(
                content=f"{prefix}-{i}", source=Source(source_type=SourceType.user_input)
            )
        )


# --- publish ----------------------------------------------------------------
def test_publishing_returns_a_receipt_with_an_inclusion_proof(
    store: LedgerStore, rekor: RekorAnchor, signer: keys.KeyPair
) -> None:
    _fill(store, 4)
    receipt = anchor_now(store, rekor, signer)

    assert receipt.backend == "rekor"
    assert receipt.statement.leaf_count == 4
    assert receipt.proof["logIndex"] == 0
    assert receipt.proof["verification"]["inclusionProof"]["treeSize"] == 1


def test_the_published_entry_carries_only_the_statement_hash(
    store: LedgerStore, rekor: RekorAnchor, signer: keys.KeyPair, fake_log: FakeRekorLog
) -> None:
    store.append(
        ProvenanceRecord(
            content="card 4111 1111 1111 1111",
            source=Source(source_type=SourceType.user_input),
        )
    )
    anchor_now(store, rekor, signer)

    stored = fake_log.entries[0].decode()
    assert "4111" not in stored
    assert json.loads(stored)["spec"]["data"]["hash"]["algorithm"] == "sha256"


def test_a_stored_receipt_re_verifies_offline(
    store: LedgerStore, rekor: RekorAnchor, signer: keys.KeyPair
) -> None:
    _fill(store, 3)
    anchor_now(store, rekor, signer)
    _fill(store, 2, prefix="more")
    anchor_now(store, rekor, signer)

    # Both receipts must still check out after the tree has grown past them,
    # which is what exercises the inclusion-proof walk rather than a trivial root.
    for receipt in AnchorStore(store.connection).anchors():
        ok, detail = rekor.verify_receipt(receipt)
        assert ok, detail


def test_publish_surfaces_a_log_error_instead_of_failing_silently(
    store: LedgerStore, rekor: RekorAnchor, signer: keys.KeyPair, fake_log: FakeRekorLog
) -> None:
    _fill(store, 2)
    fake_log.reject_next = True
    with pytest.raises(AnchorError, match="409"):
        anchor_now(store, rekor, signer)


def test_an_unreachable_log_raises_rather_than_reporting_success(
    store: LedgerStore, signer: keys.KeyPair
) -> None:
    _fill(store, 2)
    # Port 1 on loopback: nothing listens, so the connection is refused promptly.
    with pytest.raises(AnchorError, match="request failed"):
        anchor_now(store, RekorAnchor("http://127.0.0.1:1", timeout=5.0), signer)


# --- cross-check ------------------------------------------------------------
def test_a_clean_ledger_verifies_against_the_log(
    store: LedgerStore, rekor: RekorAnchor, signer: keys.KeyPair
) -> None:
    _fill(store, 5)
    anchor_now(store, rekor, signer)

    report = verify_anchors(store, rekor)
    assert report.ok, report.summary
    assert report.witness_count == 1
    # Rekor keeps no payload, so no leaf count can be read back from the log.
    assert report.witnessed_rows is None


def test_rollback_is_detected_through_the_orphaned_witness(
    tmp_path: Path, rekor: RekorAnchor, signer: keys.KeyPair
) -> None:
    # The payload-free path: matching is by fingerprint alone, so a shortened
    # ledger is caught because it cannot regenerate the statement it published.
    import sqlite3

    path = tmp_path / "ledger.db"
    store = LedgerStore(path, signer, checkpoint_every=0)
    _fill(store, 8)
    anchor_now(store, rekor, signer)
    store.close()

    con = sqlite3.connect(str(path))
    con.executescript(
        """
        DROP TRIGGER IF EXISTS ledger_no_delete;
        DROP TRIGGER IF EXISTS merkle_checkpoints_no_delete;
        DROP TRIGGER IF EXISTS anchors_no_delete;
        """
    )
    con.execute("DELETE FROM ledger WHERE seq > 4")
    con.execute("DELETE FROM merkle_checkpoints WHERE leaf_count > 4")
    con.execute("DELETE FROM anchors")
    con.commit()
    con.close()

    rolled_back = LedgerStore(path, signer, checkpoint_every=0)
    report = verify_anchors(rolled_back, rekor)
    assert not report.ok
    assert report.divergences[0].kind == DivergenceKind.ORPHANED_WITNESS


def test_a_ledger_that_never_anchored_reports_no_witness(
    store: LedgerStore, rekor: RekorAnchor
) -> None:
    _fill(store, 3)
    store.checkpoint()
    report = verify_anchors(store, rekor)
    assert not report.ok
    assert report.divergences[0].kind == DivergenceKind.NO_WITNESS


def test_witnesses_are_scoped_to_this_ledgers_signing_key(
    store: LedgerStore, rekor: RekorAnchor, signer: keys.KeyPair, tmp_path: Path
) -> None:
    _fill(store, 3)
    anchor_now(store, rekor, signer)

    # Another ledger, another key, same log: its entries must not be attributed here.
    other_signer = keys.generate()
    other = LedgerStore(tmp_path / "other.db", other_signer, checkpoint_every=0)
    _fill(other, 6)
    anchor_now(other, rekor, other_signer)

    identity = ledger_id(store.connection)
    assert identity is not None
    assert len(rekor.witnesses(identity, store.public_key)) == 1
    assert verify_anchors(store, rekor).ok
