-- External anchoring records.
--
-- One row per checkpoint statement published to an external log. The row is a
-- local *cache* of the receipt, kept so verification can re-check the log's proof
-- offline. It is not itself trusted evidence: an attacker with raw file access can
-- drop the triggers and delete these rows just as they can delete ledger rows.
--
-- The security property comes from the external log, which the attacker does not
-- control. Deleting a row here does not unpublish the statement, so verification
-- sees a witness with no matching local checkpoint -- that orphan is the tamper
-- signal (see anchor/verify.py).

CREATE TABLE IF NOT EXISTS anchors (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  checkpoint_id  INTEGER NOT NULL REFERENCES merkle_checkpoints(id),
  backend        TEXT NOT NULL,      -- 'file-witness' | 'rekor' | ...
  log_id         TEXT NOT NULL,      -- identity of the log instance
  locator        TEXT NOT NULL,      -- where the entry lives in that log
  leaf_count     INTEGER NOT NULL,   -- ledger length this statement witnesses
  root           TEXT NOT NULL,      -- blake3:<hex> anchored Merkle root
  statement_hash TEXT NOT NULL,      -- blake3:<hex> of the canonical statement
  receipt_json   TEXT NOT NULL,      -- the backend receipt, verbatim
  anchored_at    TEXT NOT NULL       -- RFC-3339 UTC publication time
);

-- Publishing the same statement twice to the same log is a no-op, not a new anchor.
CREATE UNIQUE INDEX IF NOT EXISTS idx_anchors_entry
  ON anchors(backend, log_id, locator);
CREATE INDEX IF NOT EXISTS idx_anchors_statement ON anchors(statement_hash);

CREATE TRIGGER IF NOT EXISTS anchors_no_update
BEFORE UPDATE ON anchors
BEGIN
  SELECT RAISE(ABORT, 'anchors are append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS anchors_no_delete
BEFORE DELETE ON anchors
BEGIN
  SELECT RAISE(ABORT, 'anchors are append-only: DELETE is forbidden');
END;
