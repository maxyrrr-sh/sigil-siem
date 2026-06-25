# Sigil — Frontend design document (enterprise SIEM console)

> **Status:** plan v0.1 · **MVP implemented** in [`frontend/`](../frontend/) ·
> **Scope:** the web console for Sigil (DESIGN §16/§17). A
> Splunk-/Elastic-Security-class analyst workbench over the Sigil backend, with
> Sigil's differentiator — semantic + causal correlation and the reconstructed
> attack graph — as a first-class surface, not an afterthought.

This is the design for the **production frontend**. The **full module set** is
built in [`frontend/`](../frontend/) as a lightweight Svelte SPA (~36 KB gz):
Overview, Search & Investigate, Detections, ATT&CK coverage, Alerts triage,
Incidents + interactive attack-graph, Dashboards, Hunting (notebook), Entities,
Data, Cluster, Plugins (capability review), Evaluation, and Admin. New API
endpoints added for these: `GET /incidents`, `/rules`, `/system`, `/eval`.
Remaining depth (server-side saved objects + alert mutations, the heavier viz
libs, OIDC auth — §8/§13) is the documented upgrade path. Section numbers
reference `docs/DESIGN.md`.

> **MVP simplifications** (lightweight-first; all documented upgrade paths in §3):
> plain CSS tokens (not Tailwind yet), `fetch` (not `@tanstack/svelte-query`),
> inline SVG (not Cytoscape/CodeMirror/uPlot), no OIDC yet. The thin demo at
> `GET /ui` remains as the no-JS fallback.

---

## 1. Vision & scope

A single-pane analyst + admin console that covers the full SOC loop:

**Search → Detect → Triage → Correlate → Investigate → Hunt → Report → Operate.**

Benchmarks: Splunk Enterprise Security, Elastic Security (Kibana), Google
SecOps/Chronicle, Microsoft Sentinel, Panther. Sigil's edge over all of them is
the **incident attack-graph** (causal kill-chain, ATT&CK mapping, confidence +
explanations) — the UI is built around making that explorable.

**In scope:** search/investigation, dashboards, detections (Sigma), alert
triage, incidents + attack graph, threat hunting, entity pages, ATT&CK coverage,
reporting, data/ingest management, cluster/health ops, plugins/marketplace, the
evaluation harness UI, and admin (RBAC, multi-tenant, audit, SSO).
**Out of scope (v1):** SOAR playbook authoring (link-out only), full BI.

---

## 2. Principles

1. **Data-dense but legible.** SOC tools are tables and time-series; optimize for
   scanning millions of rows, not whitespace. Compact density mode by default.
2. **Investigation is non-linear.** Everything drills down; every value is a
   pivot; deep links are shareable (URL = state).
3. **Real-time where it matters, historical everywhere.** Live tail for alerts;
   time-travel for everything.
4. **The graph is the story.** Incidents are presented as causal attack graphs +
   timelines, with the "why" (contributing edges) always visible (§9.6).
5. **Keyboard-first.** Command palette + shortcuts; an analyst should rarely
   touch the mouse.
6. **Typed end-to-end.** OpenAPI → generated client; Zod schemas mirror the
   `Event`/`Alert`/`Incident` contracts (§6, §9.6).
7. **Accessible, themeable, multi-tenant** from day one — retrofitting these is
   expensive.

---

## 3. Tech stack

> **Decision (v0.1):** a **lightweight, Splunk-feel** stack — minimal runtime,
> few heavy dependencies. This is the **Svelte** profile; a lean-React variant is
> the documented fallback if Svelte's SIEM-grade ecosystem proves limiting
> (§20 ADR-1).

| Concern | Choice | Why / alternatives |
|---|---|---|
| Language | **TypeScript (strict)** | non-negotiable for an app this size |
| Framework | **Svelte + Vite** (SvelteKit, static/SPA adapter) | tiny runtime, compiles away → lightweight. Fallback: lean React + Vite (bigger ecosystem) |
| Pkg/build | **pnpm** + Vite | fast HMR, ESM; Turborepo if it grows |
| Routing | **SvelteKit routing** + typed search-param schemas (URL-as-state) | |
| Server state | **`@tanstack/svelte-query`** | caching, polling, cursor pagination, SSE invalidation, optimistic updates |
| UI state | **Svelte stores** | ephemeral UI (layout, palette, selection); server state stays in Query |
| Design system | **Tailwind + CSS-variable tokens** + in-house `@sigil/ui`; **Melt UI / Bits UI** for a11y primitives | bespoke dense SIEM look, light footprint |
| Tables | **`@tanstack/svelte-table` + `svelte-virtual`** | headless, virtualized — million-row results |
| Query editor | **CodeMirror 6** (framework-agnostic) | syntax highlight + autocomplete for SQL & the pipe-DSL (§17) |
| Charts | **uPlot** (~40 KB) primary | search histogram + time-series; add a heavier lib only if a panel needs it (avoid ECharts by default) |
| Graphs | **Cytoscape.js** / **D3-force** | incident kill-chain DAG + provenance k-hop graphs (framework-agnostic; replaces React Flow) |
| Maps | **MapLibre GL** (lazy-loaded) | GeoIP source maps, open-source |
| Forms | **sveltekit-superforms / Felte + Zod** | shared validation; Zod = single source of types |
| Real-time | **SSE** (default) + **WebSocket** (opt) | SSE fits read-mostly live streams; WS for bidirectional |
| Auth | **OIDC / OAuth2 (Auth Code + PKCE)** (`oidc-client-ts`, framework-agnostic) | enterprise SSO/SAML via Keycloak/Okta/Entra |
| i18n | **typesafe-i18n** (light) or i18next | |
| Testing | **Vitest** + Testing Library (Svelte) + **Playwright** (e2e) + **Storybook** + **MSW** | unit/e2e/component/mocked-API |
| Quality | ESLint, Prettier, `svelte-check`, Chromatic (visual regression) | |
| Telemetry | **Sentry** + web-vitals + OTLP browser exporter | frontend observability |

**Rendering model:** authenticated internal tool → **SPA with route-based code
splitting** (no SSR needed; SEO irrelevant). Built assets are **served
separately** (static build → nginx/CDN in front of the API; the dev server
proxies `/api`). The `GET /ui` demo page stays as the no-JS fallback. (See §17.)

---

## 4. App shell & information architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│ [≡] Sigil   tenant ▾   ⌕ global search / ⌘K            🔔  live●  ⚙  user ▾   │  top bar
├──────────┬─────────────────────────────────────────────────────────────────┤
│ Overview │  ┌── Time range: Last 15m ▾  [auto-refresh ▾] ──────────────────┐ │
│ Search   │  │                                                              │ │
│ Dashbds  │  │                  ROUTE OUTLET                                │ │
│ Detect   │  │  (search results / dashboard / incident graph / …)          │ │
│ Alerts   │  │                                                              │ │
│ Incidents│  │                                                              │ │
│ Hunt     │  └──────────────────────────────────────────────────────────────┘ │
│ Entities │                                                                    │
│ ATT&CK   │                                                                    │
│ Reports  │                                                                    │
│ ───────  │                                                                    │
│ Data     │                                                                    │
│ Cluster  │                                                                    │
│ Plugins  │                                                                    │
│ Eval     │                                                                    │
│ Admin    │                                                                    │
└──────────┴────────────────────────────────────────────────────────────────────┘
```

Persistent: **global time-range picker**, **⌘K command palette**, **notifications
center**, **tenant switcher**, **live/historical toggle**, theme switch.

---

## 5. Modules / screens

Grouped by SOC workflow. Each lists key components and the backend it consumes
(✚ = endpoint that must be **added** — see §8).

### 5.1 Overview (home)
KPI tiles (events/sec, open incidents, alerts by severity, ingestion lag,
cluster health), alerts-over-time histogram, top ATT&CK techniques, recent
incidents, top noisy hosts/users. — `GET /count`, ✚`/metrics`, ✚`/incidents`.

### 5.2 Search & Investigate ⭐ (the core)
- **Query bar** (CodeMirror): toggle **pipe-DSL** ↔ **SQL** (§17); autocomplete
  on fields, commands (`search|where|stats|sort|head`), and saved searches.
- **Time picker** (relative/absolute presets) + **timeline histogram** (uPlot),
  brush-to-zoom.
- **Field sidebar**: discovered fields with top-value breakdowns + "interesting
  fields"; click → add filter / exclude / `stats by`.
- **Results grid** (virtualized): table / raw / **JSON** views; column manage;
  per-row expand to full OCSF event; every cell is a **pivot** (drilldown).
- **Save search**, share deep link, export CSV/JSON.
- Maps to `GET /search`, `/sql`, `/query`; ✚ cursor pagination, ✚ `/search/fields`
  (facets), ✚ `/search/histogram` (time buckets).

### 5.3 Dashboards
Gallery + **drag-drop builder** (grid layout, panel types: table, time-series,
single-value, bar, pie, heatmap, ATT&CK matrix, geo). **Dashboard-as-code**
(YAML/JSON, versioned, fits §13 declarative ethos). Variables/tokens, panel
**drilldowns**, scheduled PDF. — `/sql` + ✚ saved-objects API.

### 5.4 Detections — Sigma rules
Rule list (status · severity · ATT&CK · last-fired), **Sigma YAML editor**
(CodeMirror + schema validation) with the **per-rule test harness** UI (sample
events → verdict, §8), enable/disable, import SigmaHQ packs, **ATT&CK coverage**
view. — ✚ rules CRUD `/rules`, ✚`/rules/{id}/test`, ✚`/rules/import`.

### 5.5 Alerts — triage queue
Filterable queue (severity/technique/status/assignee/host), bulk actions,
**status workflow** (open → ack → closed / false-positive), assignment, notes,
SLA timers. Alert detail: matched events, rule, ATT&CK technique, raw, "create
incident". — `GET /alerts`; ✚ `PATCH /alerts/{id}` (status/assignee), ✚ bulk.

### 5.6 Incidents & attack graph ⭐ (the differentiator)
- **Incident list**: confidence, tactics chain, #events, time span, status.
- **Incident detail**:
  - **Interactive kill-chain graph** (React Flow): nodes = events/stages, edges =
    causal links with scores; click an edge → the **"why"** (shared entity, Δt,
    causal score — §9.6); ATT&CK tactic lanes.
  - **Timeline** of member events; **involved entities** (hosts/users/ips) →
    entity pages; **MITRE ATT&CK navigator** overlay; confidence + explanation
    panel; **campaign** grouping; promote to case / export.
- Consumes the `Incident { chain, tactics, techniques, confidence, explanation }`
  and `CausalGraph { nodes, edges }` types (§9.6). — ✚ `/incidents`,
  `/incidents/{id}` (returns causal graph JSON), ✚ `/incidents/{id}/timeline`.

### 5.7 Threat hunting
Ad-hoc + **saved hunts**; **notebooks** (markdown + query + viz cells, à la
Splunk/Jupyter); ATT&CK-driven hunt templates. — `/sql`,`/query` + ✚ saved hunts.

### 5.8 Entities / assets
Entity pages (host / user / ip / process): risk score, activity timeline,
related events/alerts/incidents, **provenance neighborhood graph** (k-hop, §9.4)
via Cytoscape.js. — ✚ `/entities/{kind}/{id}`, ✚ `/entities/{...}/graph`.

### 5.9 ATT&CK coverage
Full matrix heatmap: detection coverage (rules) × observed techniques (alerts) —
gaps highlighted. Drill technique → rules + recent alerts. — ✚ `/attack/coverage`.

### 5.10 Reporting
Scheduled reports (PDF/CSV), exec summaries, share links, report-as-code. — ✚.

### 5.11 Data management
Inputs/sources (status · throughput · lag · checkpoint offset), **pipeline DAG**
view (§5), codecs/parsers + normalization **preview** (raw → OCSF), template-mine
explorer (§9.2), retention/tiers + **catalog** (segments, pruning, hot/warm/cold)
(§7). — ✚ `/sources`, `/pipelines`, `/catalog/segments`, `/retention`.

### 5.12 Cluster & health
Nodes + roles (`ingest/index/correlate/query/coordinator`, §4), **shard-map
placement** visualization (§4.3), transport status, ingestion/backpressure
metrics, self-observability (Prometheus/OTLP, §15). — `sigil cluster` data ✚ as
`/cluster/*`, ✚ `/metrics`.

### 5.13 Plugins / integrations
Installed plugins + **marketplace**, the **capability-review** flow (manifest →
requested vs granted, deny-by-default approve UI, §12.2), WASM plugin status,
ML-sidecar health (§9.9). — ✚ `/plugins`, ✚ `/plugins/{id}/approve`.

### 5.14 Evaluation / research (unique to Sigil)
Run scenarios; **compare combined vs baselines/ablations** (§11.3); metric charts
(ARI/NMI, P/R/F1, alert-reduction, chain-similarity); confidence intervals over
seeds. Surfaces `sigil eval` to non-CLI users. — ✚ `/eval/run`, `/eval/reports`.

### 5.15 Admin / settings
RBAC (users/roles/permissions), **multi-tenant** management, API tokens, **audit
log**, SSO/SAML config, retention policy, notification channels (webhook/email/
Slack), license/about. — ✚ `/me`, `/rbac/*`, `/tenants`, `/audit`, `/tokens`.

---

## 6. Cross-cutting capabilities

- **Global time range** — relative/absolute, presets, per-panel override.
- **⌘K command palette** — nav, actions, saved objects, "run query".
- **Drilldown framework** — any value → new search with filter; configurable on
  dashboard panels.
- **Saved objects** — searches, dashboards, hunts, reports; ownership, sharing,
  permissions, export/import (as-code).
- **Real-time** — live toggle streams alerts/events via SSE; badges + toasts.
- **Notifications center** — alerts, system, job completion.
- **Multi-tenant** — tenant in context; all queries scoped; switcher in top bar.
- **Theming** — dark (default) / light / high-contrast via design tokens.
- **Export** — CSV / JSON / NDJSON / PDF.
- **Bulk actions, selection, keyboard nav** across all tables.

---

## 7. Data & state architecture

- **Server state → TanStack Query.** One query-key namespace per resource;
  polling or SSE invalidation for live data; **cursor pagination** for search;
  optimistic updates for triage mutations.
- **URL is state.** Search query, time range, filters, and selected tab live in
  type-safe search params (TanStack Router + Zod) → every view is a shareable
  deep link.
- **UI state → Zustand** (panel layout, palette open, density, selection).
- **Types from one source.** Backend exposes **OpenAPI** (add `utoipa` to
  `sigil-api`); generate a typed client; Zod schemas validate at the boundary and
  mirror `Event`/`Alert`/`Incident`/`CausalGraph`.
- **Web Workers** for heavy client-side parsing (large JSON, CSV export).

---

## 8. Backend API contract & gaps (critical)

The current API is read-only and minimal (`/health`, `/count`, `/search`,
`/alerts`, `/sql`, `/query`). The frontend depends on these **additions** —
treat this as the joint FE/BE work item:

| Area | New endpoints |
|---|---|
| AuthN/Z | OIDC; `GET /me`, RBAC claims, `POST /tokens` |
| Search | cursor pagination on `/search`; `/search/fields` (facets), `/search/histogram` |
| Saved objects | CRUD `/saved/{searches,dashboards,hunts,reports}` |
| Detections | CRUD `/rules`, `/rules/{id}/test`, `/rules/import`, `/attack/coverage` |
| Alerts | `PATCH /alerts/{id}` (status/assignee), bulk, notes |
| Incidents | `/incidents`, `/incidents/{id}` (+ causal graph), `/incidents/{id}/timeline` |
| Entities | `/entities/{kind}/{id}`, `/entities/{...}/graph` |
| Data ops | `/sources`, `/pipelines`, `/catalog/segments`, `/retention` |
| Cluster | `/cluster/nodes`, `/shards`, `/metrics` (Prometheus) |
| Plugins | `/plugins`, `/plugins/{id}/approve` |
| Eval | `/eval/run`, `/eval/reports` |
| Audit/tenant | `/audit`, `/tenants` |
| Real-time | **SSE** `/stream/alerts`, `/stream/events` (WS optional) |
| Spec | **OpenAPI** at `/openapi.json` for client codegen |

Recommend versioning under `/api/v1`. Many of these map to existing CLI
capabilities (`cluster`, `eval`, `plugin verify`, `correlate`) that just need an
HTTP surface.

---

## 9. Design system & theming

- **Tokens** (CSS variables): color, spacing, radius, typography, elevation,
  z-index, motion. Align to the existing dark palette in `ui.html`.
- **Themes:** dark (default), light, high-contrast; per-user persisted.
- **Density:** compact (default) / comfortable.
- **Severity & tactic color scales** standardized (critical→info; ATT&CK
  tactics) with colorblind-safe variants.
- **`@sigil/ui`** component library in Storybook: buttons, inputs, select/combo,
  table, tabs, drawer, modal, toast, badge/pill, code editor, time-picker,
  KPI tile, chart wrappers, graph canvas, ATT&CK cell, empty/skeleton states.

---

## 10. Visualization specifics

- **Results grid:** `@tanstack/svelte-table` + `svelte-virtual`; sticky header,
  column resize/pin, row expand, server-side sort/filter, 100k+ rows smooth.
- **Histogram / time-series:** uPlot for the search timeline (millions of
  points) and dashboard panels; reach for a heavier lib only if a panel needs it.
- **Attack-graph (incident):** Cytoscape.js (dagre/elk layout) — tactic
  swimlanes, edge labels = causal score, click for explanation; mini-map.
- **Provenance graph (entity):** Cytoscape.js — force/concentric layout, k-hop
  expand, large-graph perf.
- **ATT&CK matrix:** custom virtualized grid; heat by coverage/volume.
- **Geo:** MapLibre GL — source-IP clusters from GeoIP enrichment.

---

## 11. Real-time architecture

- **SSE** primary: `/stream/alerts`, `/stream/events?q=…` (server filters);
  client merges into Query cache; auto-reconnect + backfill on reconnect.
- **WebSocket** optional for bidirectional (collaborative triage, presence).
- **Live mode** is a toggle; throttle/coalesce high-rate streams; backpressure
  via server-side sampling.

---

## 12. Security

- **AuthN:** OIDC Auth-Code + PKCE; short-lived access tokens, silent refresh;
  no tokens in `localStorage` (in-memory + httpOnly refresh cookie).
- **AuthZ:** RBAC enforced **server-side**; UI hides/disables by permission only
  as UX. Tenant isolation on every request (server-scoped).
- **CSP** strict (nonce-based), Trusted Types, no inline scripts; security
  headers from axum. Sanitize any rendered log content (XSS via log data is a
  real SIEM threat).
- **No secrets in the client.** Plugin capability approvals and rule edits are
  audited.

---

## 13. Performance

- Budgets: initial route JS < 200 KB gz; TTI < 2.5s on mid hardware; 60fps
  scroll on 100k-row grids.
- Route-based code splitting + prefetch; `{#await}` + skeletons; request
  cancellation (AbortController) on query change; virtualization everywhere;
  debounced search; derived/memoized stores; Web Workers for parsing/export.
- Server-side pagination/aggregation — never pull unbounded result sets.

---

## 14. Accessibility & i18n

- **WCAG 2.1 AA:** keyboard nav, focus management, ARIA roles, visible focus,
  contrast (tokens enforce it), reduced-motion. Radix gives accessible
  primitives; graphs get table/text alternatives.
- **i18n** via i18next; all strings externalized; RTL-ready; locale-aware
  number/date/time.

---

## 15. Testing & quality

- **Unit/component:** Vitest + Testing Library; **MSW** mocks the API.
- **Component dev + visual regression:** Storybook + Chromatic.
- **E2E:** Playwright across core flows (search, triage, incident, dashboard);
  run against a seeded `sigil run` (use `seeds/`).
- **Contract tests:** validate the OpenAPI-generated client vs backend.
- CI gate: `tsc`, ESLint, Prettier, unit, a11y (axe), e2e smoke, bundle-size.

---

## 16. Repo structure & tooling

```
frontend/                      # (or web/) pnpm workspace, Svelte + Vite + TS
  src/
    routes/         SvelteKit routes, layout shell
    features/       search, alerts, incidents, dashboards, detect, hunt,
                    entities, data, cluster, plugins, eval, admin   (feature-sliced)
    components/     @sigil/ui design system (+ Storybook stories)
    lib/            api client (generated), hooks, query keys, sse, auth
    stores/         svelte stores
    types/          zod schemas mirroring backend
    test/           msw handlers, fixtures (reuse seeds/)
  e2e/              playwright
```

---

## 17. Build & deployment

> **Decision (v0.1):** serve the frontend **separately** (not embedded in the
> binary).

- `pnpm build` → static assets served by **nginx/CDN** in front of the Sigil API;
  the reverse proxy forwards `/api/v1` + SSE to `sigil-api`. The `GET /ui` demo
  page remains as the no-JS fallback.
- **Dev:** Vite dev server proxies `/api` → a local `sigil run` (seeded from
  `seeds/`).
- Add a **`web`** service to `deploy/docker-compose.yml` (static build behind
  nginx) and `web-dev` / `web-build` targets to the `Makefile`.
- CSP + security headers at the proxy (and on API responses from axum).

---

## 18. Observability (frontend)

Sentry (errors + traces), web-vitals (LCP/INP/CLS), OTLP browser exporter →
correlate FE traces with backend spans; feature-flag + A/B via a flags service.

---

## 19. Delivery roadmap

Vertical slices; each ships something usable. Maps to backend work in §8.

| Phase | Theme | Delivers |
|---|---|---|
| **F0** Foundation | Vite+TS+Tailwind+Radix+Router+Query, design tokens/themes, app shell (nav, time picker, ⌘K), **OIDC auth**, OpenAPI client + Zod, error/loading/skeletons, Storybook, CI |
| **F1** Search & Investigate ⭐ | query bar (DSL/SQL), histogram, virtualized grid, field facets, raw/JSON, drilldown, save/share/export |
| **F2** Detections & Alerts | Sigma rule list + editor + test harness, ATT&CK coverage, alert triage queue + workflow + detail |
| **F3** Incidents & Attack Graph ⭐ | incident list/detail, interactive kill-chain (React Flow), timeline, entities, confidence/explanation, ATT&CK navigator |
| **F4** Dashboards & Reporting | drag-drop builder + dashboard-as-code, ECharts panels, drilldowns, scheduled reports |
| **F5** Data / Cluster / Plugins ops | sources, pipelines, catalog/retention, cluster + shard map + metrics, plugin capability review, sidecar status |
| **F6** Hunting / Entities / Eval / Admin | notebooks, entity + provenance graph, eval harness UI, RBAC/tenants/audit/settings, i18n + a11y polish, perf + e2e hardening |

Cross-cutting (every phase): real-time (SSE), theming, a11y, perf, tests.

**MVP cut (portfolio/demo):** F0–F3 — the analyst loop end-to-end with the
attack-graph as the headline, served by the existing binary over the seed data.

**Rough effort:** MVP (F0–F3) ≈ 3–4 months with 2 FE engineers; full console ≈
6–9 months. The pacing item is the **§8 backend API**, which should be built in
lock-step (FE consumes a versioned `/api/v1` + OpenAPI).

---

## 20. Key decisions (ADRs) & risks

1. **Lightweight Svelte + TS** over React — chosen for a minimal-runtime,
   "Splunk-feel" footprint. *Fallback:* lean React + Vite if Svelte's SIEM-grade
   data-grid/graph ecosystem proves limiting (the heavy libs — CodeMirror,
   Cytoscape, uPlot, MapLibre, oidc-client-ts — are framework-agnostic, so the
   switch is contained).
2. **Tailwind + tokens + in-house `@sigil/ui`** (Melt UI / Bits UI primitives)
   over a turnkey kit — a distinctive, dense SIEM look + light footprint.
3. **REST + SSE + OpenAPI codegen** over GraphQL — simpler, matches the existing
   axum API; revisit GraphQL only if over-fetching hurts.
4. **Served separately** (nginx/CDN) over embed-in-binary — chosen for
   independent FE deploys/scaling; the `/ui` demo stays as the no-JS fallback.
5. **`@tanstack/svelte-query` (server) + Svelte stores (UI)** — clean separation
   of server vs ephemeral state, minimal boilerplate.

**Risks:** (a) the §8 backend surface is large — sequence it with the FE phases;
(b) high-cardinality search perf — solve with server-side pagination/aggregation
and virtualization; (c) graph layouts at scale — cap nodes, expand on demand;
(d) multi-tenant + RBAC must be server-enforced from F0, not bolted on.
