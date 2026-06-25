# Sigil web console

A lightweight, Splunk-style SIEM analyst console for Sigil — the **full module
set** from the plan in [`../docs/FRONTEND.md`](../docs/FRONTEND.md), ~36 KB
gzipped, zero heavy runtime deps (Svelte 5 + Vite + plain CSS + inline SVG).

- **Overview** — KPIs, recent alerts, top incident.
- **Search & Investigate** — Search/SQL/pipe-DSL bar, events histogram, results +
  JSON expand, field facets, saved searches, deep links, CSV/JSON export.
- **Detections** — Sigma rule catalog (severity / ATT&CK / fire-counts) + tactic
  coverage; **ATT&CK coverage** — tactic × technique matrix (covered vs observed).
- **Alerts** — triage queue: severity/status filters, status workflow, bulk
  actions, matched-events detail.
- **Incidents + attack-graph** — interactive SVG kill-chain (clickable stages),
  timeline, involved entities, contributing-edge "why", confidence.
- **Dashboards** — SQL-driven panels (bar/single-value/table), add/remove, saved.
- **Hunting** — notebook (markdown + runnable SQL/DSL cells), saved locally.
- **Entities** — entity explorer: ranked entities, activity, connected neighbors.
- **Data** — sources, pipelines, hot/warm/cold retention tiers, index stats.
- **Cluster** — roles, transport, shard-map placement (from `/system`).
- **Plugins** — WASM capability review (deny-by-default, mirrors `plugin verify`).
- **Evaluation** — run the harness; combined vs baselines/ablations charts.
- **Admin** — appearance/theme, node info, planned RBAC/SSO/audit surface.

Backend endpoints added for these: `/incidents`, `/rules`, `/system`, `/eval`.

> MVP simplifications (flagged in-app): client-side persistence (saved searches,
> alert status, dashboards, notebooks) is localStorage — the server-side
> saved-objects + alert-mutation endpoints are §8 backend work. The heavier viz
> (CodeMirror, Cytoscape, uPlot) and OIDC auth remain the documented upgrade path.

- **Stack:** Svelte 5 + Vite + TypeScript. Design tokens in CSS (`src/app.css`),
  typed API client (`src/lib/api.ts`), hash router, inline-SVG attack-graph.
  ~25 KB gzipped, zero runtime deps beyond Svelte.
- **Served separately:** talks to the Sigil API via `/api/*` (Vite proxy in dev,
  nginx in prod — see `nginx.conf` / `Dockerfile`).

> MVP simplifications vs the full plan (all documented upgrade paths): plain CSS
> tokens instead of Tailwind; `fetch` instead of `@tanstack/svelte-query`;
> inline SVG instead of Cytoscape/CodeMirror/uPlot; no OIDC yet (runs
> unauthenticated against a local API).

## Develop

```bash
# 1) start a backend with some data (from the repo root)
cargo run -p sigil-cli -- run --config configs/sigil.yaml   # or: make run
#    …or seed it: see ../seeds/README.md

# 2) start the web dev server (proxies /api → http://127.0.0.1:8080)
npm install && npm run dev          # or: make web-dev   (from repo root)
#    open http://localhost:5173

# point at a different API:
SIGIL_API=http://127.0.0.1:8099 npm run dev
```

## Build / preview / ship

```bash
npm run check          # svelte-check (type safety)
npm run build          # → dist/   (or: make web-build)
npm run preview        # serve dist/ locally (proxies /api too)

# container (built static + nginx, from repo root):
docker build -f frontend/Dockerfile -t sigil-web .
# or the whole stack incl. the console on :8088
docker compose -f deploy/docker-compose.yml up --build
```

## Layout

```
src/
  App.svelte            shell (topbar + sidebar + route outlet)
  app.css               design tokens + base
  lib/                  api.ts, types.ts, format.ts, router/theme (.svelte.ts)
  components/           Topbar, Sidebar, Badge, States, AttackGraph
  routes/               Overview, Search, Alerts, Incidents, Placeholder
```
