-- Provenance-DAG edges. Lives in the same database as the ledger so edge
-- endpoints can be checked for referential integrity against ledger.record_id.
-- The (src, dst, edge_type) primary key makes inserts idempotent.

CREATE TABLE IF NOT EXISTS edges (
  src        TEXT NOT NULL,
  dst        TEXT NOT NULL,
  edge_type  TEXT NOT NULL,   -- DERIVED_FROM | RETRIEVED | INFLUENCED | CONTEXTUALIZED | CONTRIBUTED_TO | ROLLED_BACK_BY
  created_at TEXT NOT NULL,
  PRIMARY KEY (src, dst, edge_type)
);

CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
