# Sigil web console

A lightweight, Splunk-style SIEM analyst console for Sigil. **MVP slice** of the
plan in [`../docs/FRONTEND.md`](../docs/FRONTEND.md): **Overview · Search &
Investigate · Alerts · Incidents + attack-graph**. The other modules are stubbed
to a "planned" placeholder.

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
