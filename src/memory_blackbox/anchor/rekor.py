"""Sigstore Rekor transparency-log backend.

Publishes each checkpoint statement as a Rekor ``rekord`` entry signed by the
ledger's Ed25519 key. Rekor is a public, append-only, Merkle-backed log operated
independently of the ledger host, which is what makes it useful here: an operator
who truncates their own ledger cannot retract what the log already recorded.

Two Rekor behaviours shape this implementation.

*Rekor persists the payload's hash, not the payload.* A ``rekord`` entry is
canonicalized down to ``spec.data.hash``, so a statement cannot be read back out
of the log. Verification therefore matches by fingerprint -- the SHA-256 of the
canonical statement, recomputed locally -- rather than by reading leaf counts from
remote entries. That is sufficient: a rolled-back ledger cannot reproduce the
statement for a checkpoint it no longer has.

*Rekor indexes entries by signing key.* ``/api/v1/index/retrieve`` returns every
entry made with a given public key, which is how verification enumerates witnesses
the local ledger may no longer admit to.

What an entry proves: this exact statement existed, in this log, at the indexed
position, no later than ``integratedTime``. It does not prove the statement is
true, that the ledger content is accurate, or that the operator anchored every
checkpoint they should have -- only gaps that the log *does* hold are detectable.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import orjson
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from memory_blackbox.anchor.base import AnchorError, CheckpointStatement, Witness
from memory_blackbox.anchor.receipt import AnchorReceipt

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from memory_blackbox.crypto.keys import KeyPair

BACKEND_NAME = "rekor"
PUBLIC_REKOR_URL = "https://rekor.sigstore.dev"

_USER_AGENT = "memory-blackbox-anchor/1"
_DEFAULT_TIMEOUT = 30.0
# Rekor responses are small (an entry with a proof is a few KB). Cap reads so a
# hostile or misconfigured endpoint cannot exhaust memory during verification.
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
# Enumerating witnesses fetches one entry per UUID; bound the work a log can force.
# Exceeding it is an error rather than a truncation: silently dropping witnesses is
# exactly how an orphaned checkpoint would go unnoticed.
_MAX_WITNESSES = 1000

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_leaf(entry: bytes) -> bytes:
    """RFC 6962 leaf hash of a log entry."""
    return _sha256(_LEAF_PREFIX + entry)


def _hash_children(left: bytes, right: bytes) -> bytes:
    """RFC 6962 internal-node hash."""
    return _sha256(_NODE_PREFIX + left + right)


def verify_inclusion(
    index: int, tree_size: int, leaf_hash: bytes, proof: list[bytes], root: bytes
) -> bool:
    """Verify an RFC 6962 inclusion proof (the algorithm from RFC 6962 §2.1.1).

    Returns True iff ``leaf_hash`` at ``index`` in a tree of ``tree_size`` leaves
    reconstructs ``root`` using ``proof``.
    """
    if index < 0 or tree_size <= 0 or index >= tree_size:
        return False
    node_index, last_index = index, tree_size - 1
    computed = leaf_hash
    for sibling in proof:
        if last_index == 0:
            return False  # more proof steps than the tree can justify
        if node_index & 1 or node_index == last_index:
            computed = _hash_children(sibling, computed)
            while node_index != 0 and node_index & 1 == 0:
                node_index >>= 1
                last_index >>= 1
        else:
            computed = _hash_children(computed, sibling)
        node_index >>= 1
        last_index >>= 1
    return last_index == 0 and computed == root


class RekorAnchor:
    """Anchors checkpoint statements to a Rekor transparency log."""

    name = BACKEND_NAME

    def __init__(
        self,
        base_url: str = PUBLIC_REKOR_URL,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        allow_insecure: bool = False,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"rekor url must be http(s): {base_url!r}")
        if parsed.scheme == "http" and not (allow_insecure or _is_loopback(parsed.hostname)):
            raise ValueError(
                f"refusing plaintext http to a non-loopback Rekor host: {base_url!r} "
                "(pass allow_insecure=True only for a trusted private network)"
            )
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = opener or urllib.request.build_opener()

    @property
    def log_id(self) -> str:
        """The configured log instance, used to scope stored anchors."""
        return self.base_url

    # -- publish ------------------------------------------------------------
    def publish(self, statement: CheckpointStatement, signer: KeyPair) -> AnchorReceipt:
        """Submit ``statement`` as a signed ``rekord`` entry and return its receipt."""
        canonical = statement.canonical()
        # Ed25519 signs the payload itself; Rekor's rekord type verifies the
        # signature against the submitted content, which is exactly this shape.
        # (hashedrekord is not usable here: it presents a pre-hashed message,
        # which pure Ed25519 cannot verify.)
        signature = signer.private_key.sign(canonical)
        entry = {
            "apiVersion": "0.0.1",
            "kind": "rekord",
            "spec": {
                "data": {"content": base64.b64encode(canonical).decode("ascii")},
                "signature": {
                    "format": "x509",
                    "content": base64.b64encode(signature).decode("ascii"),
                    "publicKey": {
                        "content": base64.b64encode(_public_pem(signer.public_key)).decode("ascii")
                    },
                },
            },
        }
        response = self._post("/api/v1/log/entries", entry)
        uuid, body = _single_entry(response)
        return AnchorReceipt(
            backend=self.name,
            log_id=self.log_id,
            locator=uuid,
            statement=statement,
            anchored_at=_integrated_at(body),
            proof={
                "uuid": uuid,
                "logIndex": body.get("logIndex"),
                "logID": body.get("logID"),
                "integratedTime": body.get("integratedTime"),
                "body": body.get("body"),
                "verification": body.get("verification", {}),
            },
        )

    # -- read back ----------------------------------------------------------
    def witnesses(self, ledger_identity: str, public_key: Ed25519PublicKey) -> list[Witness]:
        """Return every entry this log holds for the ledger's signing key.

        The returned witnesses carry no statement: Rekor keeps only the payload
        hash. ``ledger_identity`` therefore cannot be filtered on remotely, and is
        applied by the caller through fingerprint matching against local
        checkpoints -- a statement for a different ledger simply never matches.
        """
        uuids = self._search_by_public_key(public_key)
        if len(uuids) > _MAX_WITNESSES:
            raise AnchorError(
                f"the log holds {len(uuids)} entries for this key, above the "
                f"{_MAX_WITNESSES} this client will enumerate; anchor less often or "
                "narrow the key's scope rather than verifying against a partial list"
            )
        witnesses: list[Witness] = []
        for uuid in uuids:
            body = self._get_entry(uuid)
            if body is None:
                continue
            payload_hash = _payload_hash(body)
            if payload_hash is None:
                continue  # an entry of some other kind made with the same key
            witnesses.append(
                Witness(
                    backend=self.name,
                    log_id=self.log_id,
                    locator=uuid,
                    fingerprint=payload_hash,
                    statement=None,
                    integrated_at=_integrated_at(body),
                )
            )
        return witnesses

    def fingerprint(self, statement: CheckpointStatement) -> str:
        """Rekor keys a ``rekord`` by the SHA-256 of its payload."""
        return "sha256:" + hashlib.sha256(statement.canonical()).hexdigest()

    def verify_receipt(self, receipt: AnchorReceipt) -> tuple[bool, str]:
        """Re-check a stored Rekor receipt offline.

        Checks, in order: the receipt's entry body commits to this statement's
        payload hash, and the stored inclusion proof reconstructs the stored root.
        Both are done from the receipt alone -- the log is not asked to vouch for
        itself at verification time.
        """
        body_b64 = receipt.proof.get("body")
        if not isinstance(body_b64, str):
            return False, "receipt carries no entry body"
        try:
            entry_bytes = base64.b64decode(body_b64, validate=True)
        except (ValueError, TypeError):
            return False, "entry body is not valid base64"

        try:
            entry = json.loads(entry_bytes)
        except json.JSONDecodeError:
            return False, "entry body is not valid JSON"
        recorded = _payload_hash_from_entry(entry)
        expected = self.fingerprint(receipt.statement)
        if recorded != expected:
            return False, f"entry commits to {recorded}, statement hashes to {expected}"

        proof = (receipt.proof.get("verification") or {}).get("inclusionProof")
        if not isinstance(proof, dict):
            return False, "receipt carries no inclusion proof"
        try:
            index = int(proof["logIndex"])
            tree_size = int(proof["treeSize"])
            root = bytes.fromhex(str(proof["rootHash"]))
            hashes = [bytes.fromhex(str(h)) for h in proof.get("hashes", [])]
        except (KeyError, TypeError, ValueError) as exc:
            return False, f"malformed inclusion proof: {exc}"

        if not verify_inclusion(index, tree_size, _hash_leaf(entry_bytes), hashes, root):
            return False, "inclusion proof does not reconstruct the recorded root"

        checkpoint = proof.get("checkpoint")
        if (
            isinstance(checkpoint, str)
            and checkpoint
            and not _checkpoint_commits_to(checkpoint, root)
        ):
            return False, "log checkpoint does not commit to the proof's root hash"

        return True, f"inclusion proof verified at log index {index} (tree size {tree_size})"

    # -- HTTP ---------------------------------------------------------------
    def _post(self, path: str, payload: dict[str, Any]) -> Any:
        # The scheme is validated in __init__, so this is never a file:// or
        # custom-handler URL built from untrusted input.
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=orjson.dumps(payload),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": _USER_AGENT,
            },
        )
        return self._send(request)

    def _get(self, path: str) -> Any:
        request = urllib.request.Request(  # scheme validated in __init__
            f"{self.base_url}{path}",
            method="GET",
            headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
        )
        return self._send(request)

    def _send(self, request: urllib.request.Request) -> Any:
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", "replace").strip()
            raise AnchorError(f"rekor {request.get_method()} {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AnchorError(f"rekor request failed: {exc}") from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise AnchorError("rekor response exceeded the size limit")
        try:
            return orjson.loads(raw)
        except orjson.JSONDecodeError as exc:
            raise AnchorError(f"rekor returned invalid JSON: {exc}") from exc

    def _search_by_public_key(self, public_key: Ed25519PublicKey) -> list[str]:
        query = {
            "publicKey": {
                "format": "x509",
                "content": base64.b64encode(_public_pem(public_key)).decode("ascii"),
            }
        }
        try:
            found = self._post("/api/v1/index/retrieve", query)
        except AnchorError as exc:
            # An empty index legitimately 404s on some Rekor deployments.
            if " 404:" in str(exc):
                return []
            raise
        if not isinstance(found, list):
            return []
        return [str(uuid) for uuid in found]

    def _get_entry(self, uuid: str) -> dict[str, Any] | None:
        try:
            response = self._get(f"/api/v1/log/entries/{uuid}")
        except AnchorError:
            return None  # a witness we cannot fetch is reported by absence, not by raising
        try:
            _, body = _single_entry(response)
        except AnchorError:
            return None
        return body


def _is_loopback(hostname: str | None) -> bool:
    return hostname in {"localhost", "127.0.0.1", "::1"}


def _public_pem(public_key: Ed25519PublicKey) -> bytes:
    """An Ed25519 public key as a SubjectPublicKeyInfo PEM, the form Rekor indexes."""
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def _single_entry(response: Any) -> tuple[str, dict[str, Any]]:
    """Unwrap Rekor's ``{uuid: entry}`` response shape."""
    if not isinstance(response, dict) or len(response) != 1:
        raise AnchorError("unexpected rekor entry response shape")
    uuid, body = next(iter(response.items()))
    if not isinstance(body, dict):
        raise AnchorError("unexpected rekor entry body shape")
    return str(uuid), body


def _integrated_at(body: dict[str, Any]) -> str:
    integrated = body.get("integratedTime")
    if isinstance(integrated, int):
        return datetime.fromtimestamp(integrated, tz=UTC).isoformat()
    return datetime.now(UTC).isoformat()


def _payload_hash(body: dict[str, Any]) -> str | None:
    """Extract ``sha256:<hex>`` of the payload from a log entry response."""
    body_b64 = body.get("body")
    if not isinstance(body_b64, str):
        return None
    try:
        entry = json.loads(base64.b64decode(body_b64, validate=True))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    return _payload_hash_from_entry(entry)


def _payload_hash_from_entry(entry: Any) -> str | None:
    """Extract ``sha256:<hex>`` from a decoded ``rekord`` entry body."""
    if not isinstance(entry, dict) or entry.get("kind") != "rekord":
        return None
    data = (entry.get("spec") or {}).get("data") or {}
    digest = data.get("hash") or {}
    algorithm, value = digest.get("algorithm"), digest.get("value")
    if algorithm != "sha256" or not isinstance(value, str):
        return None
    return f"sha256:{value}"


def _checkpoint_commits_to(checkpoint: str, root: bytes) -> bool:
    """Return True iff a signed-tree-head note carries ``root`` as its root hash.

    The note's third line is the base64 root hash (the C2SP checkpoint format
    Rekor emits). The note's own signature is a claim by the log about itself, so
    it is not treated as independent evidence here -- this only rejects a proof
    whose checkpoint contradicts the root the proof was verified against.

    A note that is present but unreadable fails closed. An absent note is fine
    (the caller skips this check), but a malformed one is more likely a log
    dressing up a root it did not commit to than a harmless encoding quirk.
    """
    lines = checkpoint.splitlines()
    if len(lines) < 3:
        return False
    try:
        return base64.b64decode(lines[2], validate=True) == root
    except (ValueError, TypeError):
        return False
