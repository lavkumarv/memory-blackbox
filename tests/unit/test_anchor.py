"""Unit tests for anchoring primitives: statements, receipts, and proofs."""

from __future__ import annotations

import base64
import hashlib
import io
import urllib.error
from dataclasses import replace
from email.message import Message
from pathlib import Path

import orjson
import pytest

from memory_blackbox.anchor.base import (
    ANCHOR_STATEMENT_TYPE,
    Anchor,
    AnchorError,
    Checkpoint,
    CheckpointStatement,
    NoOpAnchor,
    Witness,
    ledger_id,
)
from memory_blackbox.anchor.factory import build_anchor
from memory_blackbox.anchor.file_witness import FileWitnessAnchor
from memory_blackbox.anchor.receipt import AnchorReceipt
from memory_blackbox.anchor.rekor import (
    PUBLIC_REKOR_URL,
    RekorAnchor,
    _integrated_at,
    _payload_hash,
    _payload_hash_from_entry,
    _single_entry,
    verify_inclusion,
)
from memory_blackbox.config import Config, resolve_config
from memory_blackbox.crypto import keys
from memory_blackbox.ledger.store import LedgerStore
from memory_blackbox.model.records import ProvenanceRecord, Source, SourceType


def _checkpoint(leaf_count: int = 4, root: str = "blake3:" + "ab" * 32) -> Checkpoint:
    return Checkpoint(
        checkpoint_id=1,
        leaf_count=leaf_count,
        root=root,
        signature="ed25519:" + "cd" * 64,
        signer_kid="kid-1",
        created_at="2026-01-01T00:00:00+00:00",
    )


def _statement(**overrides: object) -> CheckpointStatement:
    base = CheckpointStatement.build(_checkpoint(), "blake3:" + "ef" * 32)
    return replace(base, **overrides)  # type: ignore[arg-type]


# --- statements -------------------------------------------------------------
def test_statement_canonical_bytes_are_deterministic() -> None:
    assert _statement().canonical() == _statement().canonical()


def test_statement_carries_no_content_only_hashes_and_counts() -> None:
    parsed = orjson.loads(_statement().canonical())
    assert set(parsed) == {
        "type",
        "ledger_id",
        "signer_kid",
        "leaf_count",
        "root",
        "checkpoint_signature",
        "created_at",
    }
    assert parsed["type"] == ANCHOR_STATEMENT_TYPE


def test_statement_round_trips_through_canonical_bytes() -> None:
    statement = _statement()
    assert CheckpointStatement.from_canonical(statement.canonical()) == statement


def test_statement_digest_changes_with_leaf_count() -> None:
    # The whole rollback argument rests on this: a different length is a
    # different statement, so a shortened ledger cannot reproduce the old digest.
    assert _statement().digest() != _statement(leaf_count=5).digest()


def test_statement_rejects_unknown_type() -> None:
    raw = orjson.dumps({"type": "something-else/v9", "leaf_count": 1})
    with pytest.raises(AnchorError, match="unknown checkpoint statement type"):
        CheckpointStatement.from_canonical(raw)


def test_statement_rejects_malformed_json() -> None:
    with pytest.raises(AnchorError, match="malformed"):
        CheckpointStatement.from_canonical(b"{not json")


def test_statement_rejects_missing_fields() -> None:
    raw = orjson.dumps({"type": ANCHOR_STATEMENT_TYPE, "ledger_id": "x"})
    with pytest.raises(AnchorError, match="malformed"):
        CheckpointStatement.from_canonical(raw)


def test_statement_signature_verifies_against_the_signing_key() -> None:
    keypair = keys.generate()
    root_bytes = bytes(range(32))
    checkpoint = Checkpoint(
        checkpoint_id=1,
        leaf_count=3,
        root="blake3:" + root_bytes.hex(),
        signature=keypair.sign(root_bytes),
        signer_kid=keypair.kid,
        created_at="2026-01-01T00:00:00+00:00",
    )
    statement = CheckpointStatement.build(checkpoint, "blake3:00")
    assert statement.verify_signature(keypair.public_key)
    assert not statement.verify_signature(keys.generate().public_key)


def test_statement_signature_rejects_a_non_hex_root() -> None:
    assert not _statement(root="blake3:zz").verify_signature(keys.generate().public_key)
    assert not _statement(root="sha256:00").verify_signature(keys.generate().public_key)


# --- ledger identity --------------------------------------------------------
def test_ledger_id_is_stable_and_unique_per_ledger(tmp_path: Path) -> None:
    def build(name: str) -> str | None:
        store = LedgerStore(tmp_path / name, keys.generate())
        store.append(
            ProvenanceRecord(content="a", source=Source(source_type=SourceType.user_input))
        )
        identity = ledger_id(store.connection)
        store.close()
        return identity

    first, second = build("a.db"), build("b.db")
    assert first is not None and first.startswith("blake3:")
    assert first != second


def test_ledger_id_is_none_for_an_empty_ledger(tmp_path: Path) -> None:
    store = LedgerStore(tmp_path / "empty.db", keys.generate())
    assert ledger_id(store.connection) is None


# --- receipts ---------------------------------------------------------------
def test_receipt_round_trips_through_json() -> None:
    receipt = AnchorReceipt(
        backend="file-witness",
        log_id="blake3:00",
        locator="loc-1",
        statement=_statement(),
        anchored_at="2026-01-01T00:00:00+00:00",
        proof={"witness_signature": "ed25519:00"},
    )
    assert AnchorReceipt.from_json(receipt.to_json()) == receipt


def test_receipt_rejects_json_without_a_statement() -> None:
    with pytest.raises(AnchorError, match="missing statement"):
        AnchorReceipt.from_json('{"backend": "x"}')


# --- the no-op backend ------------------------------------------------------
def test_noop_anchor_satisfies_the_protocol() -> None:
    anchor: Anchor = NoOpAnchor()
    assert isinstance(anchor, Anchor)
    assert anchor.name == "none"
    assert anchor.witnesses("blake3:00", keys.generate().public_key) == []


def test_noop_anchor_refuses_to_publish_rather_than_pretending() -> None:
    # Silently succeeding here would be the worst possible failure: the operator
    # would believe they were anchored when nothing left the machine.
    with pytest.raises(AnchorError, match="no anchoring backend"):
        NoOpAnchor().publish(_statement(), keys.generate())


# --- witnesses --------------------------------------------------------------
def test_witness_leaf_count_is_none_without_a_statement() -> None:
    witness = Witness(
        backend="rekor", log_id="l", locator="u", fingerprint="sha256:00", statement=None
    )
    assert witness.leaf_count is None
    assert "rekor:u" in witness.describe()


def test_witness_leaf_count_comes_from_its_statement() -> None:
    statement = _statement(leaf_count=7)
    witness = Witness(
        backend="file-witness",
        log_id="l",
        locator="u",
        fingerprint=statement.digest(),
        statement=statement,
    )
    assert witness.leaf_count == 7
    assert "7 rows" in witness.describe()


# --- RFC 6962 inclusion proofs ---------------------------------------------
def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _mth(entries: list[bytes]) -> bytes:
    """Reference RFC 6962 Merkle tree hash, independent of the implementation."""
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return _leaf(entries[0])
    split = 1 << (len(entries) - 1).bit_length() - 1
    return _node(_mth(entries[:split]), _mth(entries[split:]))


def _path(index: int, entries: list[bytes]) -> list[bytes]:
    """Reference RFC 6962 inclusion path for ``index``."""
    if len(entries) <= 1:
        return []
    split = 1 << (len(entries) - 1).bit_length() - 1
    if index < split:
        return [*_path(index, entries[:split]), _mth(entries[split:])]
    return [*_path(index - split, entries[split:]), _mth(entries[:split])]


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33])
def test_inclusion_proof_verifies_for_every_leaf(size: int) -> None:
    entries = [f"entry-{i}".encode() for i in range(size)]
    root = _mth(entries)
    for index in range(size):
        assert verify_inclusion(index, size, _leaf(entries[index]), _path(index, entries), root)


def test_inclusion_proof_rejects_a_wrong_root() -> None:
    entries = [f"e-{i}".encode() for i in range(8)]
    assert not verify_inclusion(3, 8, _leaf(entries[3]), _path(3, entries), b"\x00" * 32)


def test_inclusion_proof_rejects_a_wrong_leaf() -> None:
    entries = [f"e-{i}".encode() for i in range(8)]
    assert not verify_inclusion(3, 8, _leaf(b"forged"), _path(3, entries), _mth(entries))


def test_inclusion_proof_rejects_an_out_of_range_index() -> None:
    entries = [f"e-{i}".encode() for i in range(4)]
    assert not verify_inclusion(4, 4, _leaf(entries[0]), _path(0, entries), _mth(entries))
    assert not verify_inclusion(-1, 4, _leaf(entries[0]), [], _mth(entries))
    assert not verify_inclusion(0, 0, _leaf(entries[0]), [], _mth(entries))


def test_inclusion_proof_rejects_an_over_long_proof() -> None:
    entries = [b"only-one"]
    assert not verify_inclusion(0, 1, _leaf(entries[0]), [b"\x11" * 32], _mth(entries))


# --- rekor backend construction --------------------------------------------
def test_rekor_rejects_a_non_http_url() -> None:
    with pytest.raises(ValueError, match="must be http"):
        RekorAnchor("ftp://example.invalid")


def test_rekor_refuses_plaintext_to_a_remote_host() -> None:
    with pytest.raises(ValueError, match="plaintext http"):
        RekorAnchor("http://rekor.example.invalid")


def test_rekor_allows_plaintext_to_loopback_for_local_testing() -> None:
    assert RekorAnchor("http://127.0.0.1:8080").base_url == "http://127.0.0.1:8080"


def test_rekor_fingerprint_is_the_sha256_of_the_canonical_statement() -> None:
    statement = _statement()
    expected = "sha256:" + hashlib.sha256(statement.canonical()).hexdigest()
    assert RekorAnchor().fingerprint(statement) == expected


# --- configuration ----------------------------------------------------------
def test_anchoring_is_off_by_default() -> None:
    assert Config().anchor_backend == "none"
    assert Config().anchoring is False


def test_config_reads_the_anchoring_backend_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MEMORY_BLACKBOX_ANCHOR", "file")
    monkeypatch.setenv("MEMORY_BLACKBOX_ANCHOR_WITNESS", str(tmp_path / "w.jsonl"))
    config = resolve_config(tmp_path)
    assert config.anchoring
    assert config.default_witness_path == tmp_path / "w.jsonl"


def test_config_rejects_an_unknown_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEMORY_BLACKBOX_ANCHOR", "carrier-pigeon")
    with pytest.raises(ValueError, match="not a known anchoring backend"):
        resolve_config(tmp_path)


def test_witness_defaults_into_the_profile_directory(tmp_path: Path) -> None:
    assert Config(home=tmp_path).default_witness_path == tmp_path / "witness.jsonl"


# --- rekor receipt verification, failure by failure -------------------------
# A hostile or buggy log is the case that matters here: every one of these paths
# must return a reasoned False rather than raising, or defaulting to True.
def _rekor_receipt(**proof: object) -> AnchorReceipt:
    return AnchorReceipt(
        backend="rekor",
        log_id="https://rekor.example",
        locator="uuid-1",
        statement=_statement(),
        anchored_at="2026-01-01T00:00:00+00:00",
        proof=dict(proof),
    )


def _rekord_body(payload: bytes) -> str:
    entry = {
        "apiVersion": "0.0.1",
        "kind": "rekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": hashlib.sha256(payload).hexdigest()}},
            "signature": {"format": "x509", "content": "", "publicKey": {"content": ""}},
        },
    }
    return base64.b64encode(orjson.dumps(entry, option=orjson.OPT_SORT_KEYS)).decode("ascii")


def test_rekor_receipt_without_a_body_is_rejected() -> None:
    ok, detail = RekorAnchor().verify_receipt(_rekor_receipt())
    assert not ok
    assert "no entry body" in detail


def test_rekor_receipt_with_a_non_base64_body_is_rejected() -> None:
    ok, detail = RekorAnchor().verify_receipt(_rekor_receipt(body="not!base64!"))
    assert not ok
    assert "base64" in detail


def test_rekor_receipt_with_a_non_json_body_is_rejected() -> None:
    body = base64.b64encode(b"{definitely not json").decode("ascii")
    ok, detail = RekorAnchor().verify_receipt(_rekor_receipt(body=body))
    assert not ok
    assert "valid JSON" in detail


def test_rekor_receipt_whose_entry_commits_to_another_payload_is_rejected() -> None:
    # The log entry must be about *this* statement; anything else is a receipt
    # borrowed from a different checkpoint.
    ok, detail = RekorAnchor().verify_receipt(_rekor_receipt(body=_rekord_body(b"other payload")))
    assert not ok
    assert "statement hashes to" in detail


def test_rekor_receipt_without_an_inclusion_proof_is_rejected() -> None:
    statement = _statement()
    ok, detail = RekorAnchor().verify_receipt(
        _rekor_receipt(body=_rekord_body(statement.canonical()), verification={})
    )
    assert not ok
    assert "no inclusion proof" in detail


def test_rekor_receipt_with_a_malformed_inclusion_proof_is_rejected() -> None:
    statement = _statement()
    ok, detail = RekorAnchor().verify_receipt(
        _rekor_receipt(
            body=_rekord_body(statement.canonical()),
            verification={"inclusionProof": {"logIndex": "not-a-number"}},
        )
    )
    assert not ok
    assert "malformed inclusion proof" in detail


def test_rekor_receipt_with_a_proof_that_does_not_reconstruct_the_root_is_rejected() -> None:
    statement = _statement()
    ok, detail = RekorAnchor().verify_receipt(
        _rekor_receipt(
            body=_rekord_body(statement.canonical()),
            verification={
                "inclusionProof": {
                    "logIndex": 0,
                    "treeSize": 1,
                    "rootHash": "00" * 32,
                    "hashes": [],
                }
            },
        )
    )
    assert not ok
    assert "does not reconstruct" in detail


def _valid_single_entry_proof(statement: CheckpointStatement) -> dict[str, object]:
    """A genuine one-leaf proof: the root of a single-entry tree is its leaf hash."""
    entry = base64.b64decode(_rekord_body(statement.canonical()))
    root = hashlib.sha256(b"\x00" + entry).digest()
    return {
        "logIndex": 0,
        "treeSize": 1,
        "rootHash": root.hex(),
        "hashes": [],
        "checkpoint": f"log\n1\n{base64.b64encode(root).decode('ascii')}\n",
    }


def test_rekor_receipt_with_a_genuine_proof_is_accepted() -> None:
    statement = _statement()
    ok, detail = RekorAnchor().verify_receipt(
        _rekor_receipt(
            body=_rekord_body(statement.canonical()),
            verification={"inclusionProof": _valid_single_entry_proof(statement)},
        )
    )
    assert ok, detail
    assert "log index 0" in detail


def test_rekor_receipt_is_rejected_when_the_checkpoint_contradicts_the_proof() -> None:
    statement = _statement()
    proof = _valid_single_entry_proof(statement)
    proof["checkpoint"] = "log\n1\n" + base64.b64encode(b"\x99" * 32).decode("ascii") + "\n"
    ok, detail = RekorAnchor().verify_receipt(
        _rekor_receipt(
            body=_rekord_body(statement.canonical()),
            verification={"inclusionProof": proof},
        )
    )
    assert not ok
    assert "checkpoint does not commit" in detail


def test_rekor_accepts_a_proof_that_carries_no_checkpoint_note() -> None:
    # Not every deployment returns a note. Absent is not a contradiction, so the
    # inclusion proof alone decides.
    statement = _statement()
    proof = _valid_single_entry_proof(statement)
    proof["checkpoint"] = ""
    ok, detail = RekorAnchor().verify_receipt(
        _rekor_receipt(
            body=_rekord_body(statement.canonical()),
            verification={"inclusionProof": proof},
        )
    )
    assert ok, detail


@pytest.mark.parametrize("checkpoint", ["too\nshort", "log\n1\nnot-base64!!\n"])
def test_rekor_rejects_a_checkpoint_note_it_cannot_read(checkpoint: str) -> None:
    # A note that is present but unreadable fails closed: it may well be a log
    # trying to look like it committed to a root it did not.
    statement = _statement()
    proof = _valid_single_entry_proof(statement)
    proof["checkpoint"] = checkpoint
    ok, detail = RekorAnchor().verify_receipt(
        _rekor_receipt(
            body=_rekord_body(statement.canonical()),
            verification={"inclusionProof": proof},
        )
    )
    assert not ok
    assert "checkpoint does not commit" in detail


# --- backend selection ------------------------------------------------------
def test_build_anchor_returns_the_no_op_backend_by_default(tmp_path: Path) -> None:
    assert build_anchor(Config(home=tmp_path)).name == "none"


def test_build_anchor_returns_a_file_witness(tmp_path: Path) -> None:
    anchor = build_anchor(Config(home=tmp_path, anchor_backend="file"))
    assert isinstance(anchor, FileWitnessAnchor)
    assert anchor.path == tmp_path / "witness.jsonl"


def test_build_anchor_returns_a_rekor_client_at_the_configured_url(tmp_path: Path) -> None:
    anchor = build_anchor(
        Config(home=tmp_path, anchor_backend="rekor", rekor_url="https://rekor.example")
    )
    assert isinstance(anchor, RekorAnchor)
    assert anchor.base_url == "https://rekor.example"


def test_build_anchor_defaults_rekor_to_the_public_log(tmp_path: Path) -> None:
    anchor = build_anchor(Config(home=tmp_path, anchor_backend="rekor"))
    assert isinstance(anchor, RekorAnchor)
    assert anchor.base_url == PUBLIC_REKOR_URL


def test_build_anchor_rejects_an_unknown_backend(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown anchoring backend"):
        build_anchor(Config(home=tmp_path, anchor_backend="telepathy"))


# --- reading a misbehaving log ---------------------------------------------
# Verification talks to a log it does not control, so every one of these shapes
# has to produce either a clear AnchorError or a clean "not a witness" -- never a
# crash, and never a silent pass.
def test_entry_response_must_hold_exactly_one_entry() -> None:
    with pytest.raises(AnchorError, match="entry response shape"):
        _single_entry({"a": {}, "b": {}})
    with pytest.raises(AnchorError, match="entry response shape"):
        _single_entry([])


def test_entry_body_must_be_an_object() -> None:
    with pytest.raises(AnchorError, match="entry body shape"):
        _single_entry({"uuid": "not-an-object"})


def test_integrated_at_falls_back_to_now_when_the_log_omits_a_timestamp() -> None:
    assert _integrated_at({"integratedTime": 1_700_000_000}).startswith("2023-11-14")
    assert _integrated_at({}).startswith("20")  # a valid ISO timestamp, not a crash


@pytest.mark.parametrize(
    "body",
    [
        {},  # no body at all
        {"body": 42},  # body is not a string
        {"body": "not!base64"},  # body is not decodable
        {"body": base64.b64encode(b"{not json").decode("ascii")},
    ],
)
def test_an_unreadable_entry_body_yields_no_payload_hash(body: dict[str, object]) -> None:
    assert _payload_hash(body) is None


@pytest.mark.parametrize(
    "entry",
    [
        "a string, not an entry",
        {"kind": "hashedrekord"},  # some other entry type made with the same key
        {"kind": "rekord", "spec": {}},  # rekord with no data hash
        {"kind": "rekord", "spec": {"data": {"hash": {"algorithm": "sha512", "value": "ab"}}}},
        {"kind": "rekord", "spec": {"data": {"hash": {"algorithm": "sha256", "value": 7}}}},
    ],
)
def test_an_entry_that_is_not_a_sha256_rekord_is_not_a_witness(entry: object) -> None:
    assert _payload_hash_from_entry(entry) is None


def test_a_well_formed_rekord_yields_its_payload_hash() -> None:
    entry = {
        "kind": "rekord",
        "spec": {"data": {"hash": {"algorithm": "sha256", "value": "ab" * 32}}},
    }
    assert _payload_hash_from_entry(entry) == "sha256:" + "ab" * 32


class _StubOpener:
    """Stands in for urllib's opener so HTTP failure modes can be exercised."""

    def __init__(self, response: object) -> None:
        self.response = response

    def open(self, request: object, timeout: float | None = None) -> object:
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class _StubResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self, size: int | None = None) -> bytes:
        return self._payload if size is None else self._payload[:size]

    def __enter__(self) -> _StubResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def _anchor_with(response: object) -> RekorAnchor:
    return RekorAnchor("https://rekor.example", opener=_StubOpener(response))  # type: ignore[arg-type]


def test_a_non_json_response_is_an_anchor_error() -> None:
    with pytest.raises(AnchorError, match="invalid JSON"):
        _anchor_with(_StubResponse(b"<html>gateway error</html>")).witnesses(
            "blake3:00", keys.generate().public_key
        )


def test_an_oversized_response_is_refused_rather_than_buffered() -> None:
    with pytest.raises(AnchorError, match="exceeded the size limit"):
        _anchor_with(_StubResponse(b"[" + b" " * (9 * 1024 * 1024))).witnesses(
            "blake3:00", keys.generate().public_key
        )


def test_a_network_failure_is_an_anchor_error() -> None:
    with pytest.raises(AnchorError, match="request failed"):
        _anchor_with(urllib.error.URLError("connection refused")).witnesses(
            "blake3:00", keys.generate().public_key
        )


def test_an_http_error_carries_the_logs_own_message() -> None:
    error = urllib.error.HTTPError(
        "https://rekor.example",
        422,
        "Unprocessable",
        Message(),
        io.BytesIO(b"kind in body is required"),
    )
    with pytest.raises(AnchorError, match="kind in body is required"):
        _anchor_with(error).witnesses("blake3:00", keys.generate().public_key)


def test_an_empty_index_that_404s_means_no_witnesses_not_an_error() -> None:
    # Some Rekor deployments 404 an index lookup that matches nothing. That is
    # "you have never anchored", which the caller reports as NO_WITNESS.
    error = urllib.error.HTTPError(
        "https://rekor.example", 404, "Not Found", Message(), io.BytesIO(b"")
    )
    assert _anchor_with(error).witnesses("blake3:00", keys.generate().public_key) == []


def test_an_index_response_that_is_not_a_list_yields_no_witnesses() -> None:
    anchor = _anchor_with(_StubResponse(b'{"unexpected": "shape"}'))
    assert anchor.witnesses("blake3:00", keys.generate().public_key) == []
