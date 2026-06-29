# Sidecar example

A reverse proxy in front of a hosted vector DB (Pinecone, Qdrant Cloud, Weaviate,
Mongo Atlas). It intercepts upsert/query, records signed provenance, forwards the
request upstream, and tags upserts with the provenance record id so each stored
vector points back to its ledger entry.

```bash
python examples/sidecar/run.py
```

You declare which operations are upserts vs queries and how to read their
payloads/results (`WriteMap`/`ReadMap`). The core is transport-agnostic —
`forward(op, payload)` is the single seam to your hosted DB's HTTP/gRPC API; deploy
it as a process or a Kubernetes sidecar.
