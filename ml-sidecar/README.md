# Sigil ML sidecar

Python sidecar for the semantic + causal correlation engine
(see [../docs/DESIGN.md](../docs/DESIGN.md) §9). It talks to the Rust core over
gRPC + Arrow Flight.

**Responsibilities:** event/alert embeddings, the HNSW vector index, GNN /
causal scoring, and the optional GRAIN-style RL path selection.

**Status:** scaffold stub.

```bash
python -m sidecar.server   # prints the planned interface (not serving yet)
```
