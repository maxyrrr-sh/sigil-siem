# Sigil SIEM

> **Status: all roadmap phases (0–6) implemented.** A single binary that
> ingests → normalizes → indexes → searches from declarative config, with a
> native Sigma engine emitting ATT&CK-tagged alerts, a Parquet cold tier
> queryable via SQL + a pipe-DSL (DataFusion), semantic cross-domain correlation
> into campaign candidates, causal reconstruction of multi-stage kill-chains
> mapped to ATT&CK (confidence + explanations), config-selectable roles +
> transport/shard abstraction, a capability-gated WASM plugin sandbox, and an
> evaluation harness + served attack-graph UI. Remaining work is depth within
> phases (trained ML models, live multi-node cluster, real datasets) — see the
> per-phase ◐ items.

Open-source **SIEM** written in Rust — a single binary that scales vertically
and horizontally, with its own indexer, native **Sigma** support, a tiered
plugin system, and **declarative-first** configuration.

**Headline feature:** semantic + causal correlation of heterogeneous security
events (vector embeddings + a causal provenance graph) to reconstruct
multi-stage attacks and map them to MITRE ATT&CK.

## Documentation

- **[docs/DESIGN.md](docs/DESIGN.md)** — full design: architecture, indexer,
  Sigma engine, correlation feature, evaluation methodology, roadmap.
- **[docs/FRONTEND.md](docs/FRONTEND.md)** — the web console design (Splunk-style
  analyst workbench); an MVP is implemented in **[`frontend/`](frontend/)**.
- **[CLAUDE.md](CLAUDE.md)** — contributor / agent guide and crate map.

## Web console

A lightweight Svelte SPA (Overview · Search · Alerts · Incidents + attack-graph)
talks to the API and reconstructs kill-chains live. Run a backend, then:

```bash
make web-dev        # dev server at http://localhost:5173 (proxies /api → :8080)
# or the whole stack incl. the console on :8088:
docker compose -f deploy/docker-compose.yml up --build
```

## Layout

```
crates/       Rust workspace (crate map in CLAUDE.md)
ml-sidecar/   Python ML sidecar (embeddings, vector index, GNN)
configs/      Example declarative configuration
deploy/       docker-compose dev stack
docs/         Design documentation
```

## Quickstart (scaffold)

```bash
cargo run -p sigil-cli -- help     # the `sigil` CLI (stub)
cargo build                        # default members (excludes optional RL module)
```

## Roadmap

The roadmap is organized as **vertical slices**: each phase ships something
runnable end-to-end rather than a horizontal layer in isolation. The aim is a
usable SIEM early (Phases 0–2), with the research differentiator — semantic +
causal correlation — built and *measured* in Phases 3–4 and 6.

Legend: ☐ planned · ◐ in progress · ☑ done. **All phases (0–6) are implemented**; remaining work is depth (◐ items).

### Overview

| Phase | Theme | Exit milestone |
|------:|-------|----------------|
| 0 ✅ | Foundations | Events ingested, indexed, searchable; declarative config applies |
| 1 ✅ | Detection | Sigma alerts out of the box |
| 2 ✅ | Indexer maturity | Long retention + analytical queries across tiers |
| 3 ✅ | Semantics | Cross-domain campaign *candidates* from embeddings + graph |
| 4 ✅ | Causality & attribution | Reconstructed multi-stage kill-chain mapped to ATT&CK |
| 5 ✅ | Scale-out & plugins | One binary: monolith → cluster; community WASM plugins |
| 6 ✅ | Evaluation & UI | Measured attribution accuracy + attack-graph UI |

### Phase 0 — Foundations

**Goal:** a single binary that ingests, normalizes, indexes, and searches events, fully driven by declarative config.

- [x] `sigil-core`: `Event`/OCSF model (`OcsfClass`, `Severity`, `EntityRef`), error types, plugin traits
- [x] `sigil-ingest`: `file` (tail + checkpoint) and `syslog` (UDP/TCP) inputs; `json` and `syslog` codecs
- [x] `sigil-normalize`: OCSF mapping for syslog / auth / network / HTTP / JSON shapes
- [x] `sigil-index`: Tantivy-backed hot segment; write + full-text search, newest-first
- [x] `sigil-api`: read-only HTTP search (`/health`, `/count`, `/search?q=&limit=`)
- [x] `sigil-cli`: real `run`, `replay`, and `config validate` wired up
- [◐] `sigil-config`: YAML loader + semantic `validate` done; JSON Schema, `plan`/`apply`, hot-reload pending

**Crates:** core, config, ingest, normalize, index, api, cli
**Exit (met):** `sigil run` ingests syslog (live-tailed files too), results are searchable via the API, and the whole node is defined in `configs/sigil.yaml`. Try it:

```bash
sigil config validate configs/sigil.yaml      # schema + semantic checks
sigil replay /var/log/auth.log --codec syslog  # deterministic file → index
sigil run --config configs/sigil.yaml          # live inputs + query API on :8080
curl 'http://127.0.0.1:8080/search?q=failed&limit=20'
```

### Phase 1 — Detection (Sigma)

**Goal:** detections out of the box using the Sigma standard.

- [x] `sigil-sigma`: Sigma YAML → AST → streaming predicate over OCSF events (modifiers, wildcards, `N of`, `and/or/not`)
- [x] Per-rule unit-test harness (sample events → expected verdict)
- [x] Alerting outputs: webhook + file (JSON lines) + in-memory store with `GET /alerts`
- [◐] Field-mapping (Sigma → OCSF/ECS): built-in aliases done; configurable pipelines pending
- [◐] Rulepack loading: recursive `rules_dir` loading done; versioning/signing + SigmaHQ import pending
- [◐] Pipeline routing: per-sink routing (`index`/`sigma`) + decode dead-lettering done; full conditional DAG pending
- [ ] Enrichment: GeoIP, threat-intel (MISP/STIX-TAXII), asset/identity lookup — deferred
- [ ] Sigma *correlation* rules (`temporal`, `event_count`) — deferred to align with Phase 9 work

**Crates:** sigma, normalize, ingest, api, cli
**Exit (met):** load a Sigma rulepack, feed events, get alerts carrying ATT&CK technique tags. Try it:

```bash
sigil replay /var/log/auth.log --codec syslog   # prints matched alerts + techniques
sigil run --config configs/sigil.yaml            # live detection; alerts → file + /alerts
curl 'http://127.0.0.1:8080/alerts?technique=T1110.001'
```

Example rules live in [`configs/rules/`](configs/rules/) (SSH brute force, `/etc/shadow` access, sudo-to-root).

### Phase 2 — Indexer maturity

**Goal:** real retention and analytics, not just hot search.

- [x] DataFusion analytical queries over Arrow/Parquet (aggregations) — `GET /sql`, `sigil query`
- [x] Catalog with segment metadata + segment pruning (time-overlap) — JSON catalog
- [x] Query language v1: pipe-DSL lowering to SQL over DataFusion (SQL also exposed) — `GET /query`, `sigil query`
- [x] Cold tier in Parquet (rollover by size/time) behind a storage abstraction
- [◐] Declarative retention / rollover: rollover + age-based retention deletion done; warm-tier transitions pending
- [◐] Tiered storage hot → warm → cold: hot (Tantivy) + cold (Parquet) + retention done; warm tier + hot→cold migration pending
- [ ] Object-store backend (`object_store`: S3/MinIO): local Parquet ships; S3 slots behind the same abstraction — deferred

**Crates:** index, api, config
**Exit (met):** analytical queries return over historical data on cheap columnar (Parquet) storage with configurable retention. Try it:

```bash
sigil query "SELECT ocsf_class_name, count(*) AS n FROM events GROUP BY ocsf_class_name"
sigil query 'search failed | stats count() as hits by host | sort hits desc'   # pipe-DSL
curl --get 'http://127.0.0.1:8080/query' --data-urlencode 'q=stats count() by severity'
```

### Phase 3 — Semantics

**Goal:** first half of the research feature — represent and link heterogeneous events.

- [x] `sigil-ingest`: online template mining (Drain-style) → `template_id` + variables
- [x] Triplet extraction `(subject, action, object)` per event
- [x] `sigil-graph`: provenance graph store (entities = nodes, events = edges) + k-hop + shared-entity lookup
- [x] Cross-domain candidate generation: vector KNN + shared entities + time window → connected components
- [x] Semantic linking → campaign *candidates* (`sigil correlate`)
- [◐] `ml-sidecar`: real gRPC server (Health/Embed/Score); deterministic hashing embedder ships, SecureBERT behind the `model` extra; Arrow Flight + Rust→sidecar gRPC client (tonic) deferred
- [◐] Vector index: `VectorStore` trait + exact cosine KNN ships; embedded HNSW (`usearch`/`hnsw_rs`) backend deferred behind the trait

**Crates:** ingest, graph, correlate, + ml-sidecar
**Exit (met):** for a multi-stage scenario, the system surfaces cross-domain event groups that plausibly belong to one campaign. Try it:

```bash
sigil correlate scenario.jsonl --codec json     # → cross-domain campaign candidates
sigil correlate scenario.jsonl --window 30m      # tune the link window
```

> Embeddings use a deterministic offline hashing embedder by default (lexical
> similarity), so correlation runs with no model download; the ML sidecar
> (`python -m sidecar.server`) provides the same contract with a real semantic
> model as a drop-in.

### Phase 4 — Causality & attribution

**Goal:** second half — turn candidates into a causal attack graph and attribute it.

- [x] Causal scoring of edges (temporal + shared-entity + anomaly) over a time-ordered causal graph
- [x] Chain assembly via beam-search over the causal score (default `PathSelector`)
- [x] Incident object = causal attack graph; ATT&CK tactic → technique mapping
- [x] Confidence + explanation (contributing edges)
- [x] **Optional module** `sigil-correlate-rl`: GRAIN-style RL path selection (off by default, drop-in `PathSelector`)
- [◐] Self-supervised anomaly scoring: deterministic anomaly heuristic ships; masked-graph-autoencoder (MAGIC) model deferred to the sidecar
- [◐] GNN node/subgraph embeddings (GraphSAGE/GAT): sidecar `Score` contract exists; trained model deferred (needs PyTorch + datasets)

**Crates:** correlate, graph, correlate-rl (optional), + ml-sidecar
**Exit (met):** a time-ordered, reconstructed kill-chain for a known scenario, mapped to ATT&CK, with a confidence score. Try it:

```bash
sigil correlate killchain.log --codec syslog   # → reconstructed incident + ATT&CK chain
```

Example output: `credential-access → privilege-escalation` with techniques `T1110.001`,
`T1548.003`, a confidence score, and per-edge "why" explanations. Causal/anomaly
scoring is heuristic today (a deterministic stand-in for the GNN/MAGIC model);
swap the model in behind the sidecar `Score` contract.

### Phase 5 — Scale-out & plugins

**Goal:** deliver the "monolith that scales" and the extensibility story.

- [x] Role targets (`ingest/index/correlate/query/coordinator`) selectable via config; gated in the run loop
- [x] Transport abstraction: `Transport` trait + in-proc bus (Redpanda/Kafka + NATS slot in behind it)
- [x] Index sharding (time + hash) + replication placement (`ShardMap`)
- [x] `sigil-plugin-wasm`: wasmtime host running sandboxed WASM modules; WIT interface in `wit/processor.wit`
- [x] Capability-based plugin permissions (deny-by-default); plugin manifest (`sigil plugin verify`)
- [◐] Raft catalog (`openraft`): shard map + membership data model ships; consensus/replication across nodes deferred
- [◐] Full Component Model + wit-bindgen (core modules run today); plugin signature verification deferred
- [◐] Redpanda/Kafka + NATS transport backends + live multi-node cluster (need a broker; behind the trait)

**Crates:** cluster, plugin-wasm, index, config
**Exit (met, single-binary):** roles are config-selectable and gated; the shard map places shards across N nodes with replication; a sandboxed WASM plugin runs under capability control. Try it:

```bash
sigil cluster --config cluster.yaml             # roles, transport, shard placement
sigil plugin verify plugin.json --allow read:field:message   # capability check
```

> Live multi-node clustering over a real broker is the remaining distributed
> piece; the role/transport/shard abstractions and the WASM sandbox are in place.

### Phase 6 — Evaluation & UI

**Goal:** prove the research claim and make it demonstrable.

- [x] `sigil-eval` harness: run the pipeline over labelled scenarios and score it
- [x] Metrics: detection (P/R/F1), correlation (ARI/NMI, alert-reduction ratio), attribution (technique-chain P/R, graph edit distance / chain similarity)
- [x] Baselines + ablations: combined vs sigma-only, provenance-only, semantic-only (±embeddings, ±provenance knobs on `CampaignConfig`)
- [x] Reproducible runs: deterministic synthetic scenario with a pinned `--seed`
- [x] Web UI: served triage dashboard (`GET /ui`) with live alerts + an SVG attack-graph
- [◐] Dataset loaders (DARPA TC/OpTC, ATLAS) + Caldera/Atomic-Red-Team generator — synthetic generator ships; real loaders slot behind the `Scenario` shape
- [◐] Confidence intervals over many seeds; ±GNN / ±RL ablation rows (RL is opt-in)

**Crates:** eval (new), api (+UI), correlate
**Exit (met):** a reproducible report quantifying correlation/attribution of the combined approach vs each component, plus a served attack-graph UI. Try it:

```bash
sigil eval --seed 1     # comparison table: combined vs baselines/ablations
sigil run               # then open http://127.0.0.1:8080/ui
```

> On the bundled synthetic scenario `combined` reaches ARI/NMI/chain-similarity
> 1.00 with 0.75 alert-reduction, vs the sigma-only baseline at ARI 0.90,
> chain-similarity 0.00. Real datasets + multi-seed confidence intervals are the
> remaining research steps; metrics/harness/UI are in place.

### MVP (portfolio target)

Phases **0–1** end to end, plus a **thin vertical slice of 3–4**: one provenance
source (e.g. a DARPA TC subset) → embeddings → graph → a simple GNN/causal score
producing one reconstructed attack chain. This already demonstrates both the
engineering and the research idea.

### Cross-cutting (every phase)

- [ ] **Security**: mTLS between nodes/sidecar, RBAC, secrets via external providers, audit log
- [ ] **Observability**: Prometheus self-metrics, OTLP tracing, health endpoints
- [ ] **Quality**: CI (fmt, clippy, tests), `cargo deny` / `audit`, golden tests for parsers and rules
- [ ] **Docs**: keep `docs/DESIGN.md` and ADRs in sync with the code

> Per-component design for each item lives in [`docs/DESIGN.md`](docs/DESIGN.md).
> This roadmap is the sequencing view; DESIGN is the reference.

## License

Apache-2.0 (intended).
