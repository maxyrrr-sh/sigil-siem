<script lang="ts">
  import { router } from './lib/router.svelte';
  import Topbar from './components/Topbar.svelte';
  import Sidebar from './components/Sidebar.svelte';
  import Overview from './routes/Overview.svelte';
  import Search from './routes/Search.svelte';
  import Alerts from './routes/Alerts.svelte';
  import Incidents from './routes/Incidents.svelte';
  import Placeholder from './routes/Placeholder.svelte';

  type PlannedMeta = { title: string; phase: string; blurb: string };
  const planned: Record<string, PlannedMeta> = {
    '/detections': { title: 'Detections', phase: 'F2', blurb: 'Sigma rule management: list, YAML editor with the per-rule test harness, enable/disable, SigmaHQ import.' },
    '/attack': { title: 'ATT&CK coverage', phase: 'F2', blurb: 'MITRE ATT&CK matrix heatmap — detection coverage × observed techniques, with gaps highlighted.' },
    '/dashboards': { title: 'Dashboards', phase: 'F4', blurb: 'Drag-drop panel builder + dashboard-as-code, drilldowns and scheduled reports over the SQL/DSL engine.' },
    '/hunt': { title: 'Threat hunting', phase: 'F6', blurb: 'Ad-hoc + saved hunts and notebooks (markdown + query + viz cells).' },
    '/entities': { title: 'Entities', phase: 'F6', blurb: 'Host / user / ip / process pages: timeline, related events, risk, and a k-hop provenance neighborhood graph.' },
    '/data': { title: 'Data management', phase: 'F5', blurb: 'Inputs/sources health, pipeline DAG, normalization preview, retention/tiers and the segment catalog.' },
    '/cluster': { title: 'Cluster & health', phase: 'F5', blurb: 'Nodes, roles, the shard-map placement, transport status and ingestion metrics (maps to `sigil cluster`).' },
    '/plugins': { title: 'Plugins', phase: 'F5', blurb: 'Installed plugins + marketplace and the capability-review approval flow (maps to `sigil plugin verify`).' },
    '/eval': { title: 'Evaluation', phase: 'F6', blurb: 'Run scenarios and compare combined vs baselines/ablations with metric charts (maps to `sigil eval`).' },
    '/admin': { title: 'Admin', phase: 'F6', blurb: 'RBAC, multi-tenant, API tokens, audit log and SSO configuration.' },
  };
</script>

<div class="shell">
  <header class="topbar"><Topbar /></header>
  <aside class="sidebar"><Sidebar /></aside>
  <main class="main">
    {#if router.path === '/'}
      <Overview />
    {:else if router.path === '/search'}
      <Search />
    {:else if router.path === '/alerts'}
      <Alerts />
    {:else if router.path === '/incidents'}
      <Incidents />
    {:else if planned[router.path]}
      <Placeholder {...planned[router.path]} />
    {:else}
      <Placeholder title="Not found" phase="404" blurb={`No view for ${router.path}.`} />
    {/if}
  </main>
</div>

<style>
  .shell {
    display: grid;
    grid-template-columns: 220px 1fr;
    grid-template-rows: 52px 1fr;
    grid-template-areas: 'top top' 'side main';
    height: 100vh;
  }
  .topbar { grid-area: top; background: var(--surface); border-bottom: 1px solid var(--border); }
  .sidebar { grid-area: side; background: var(--surface); border-right: 1px solid var(--border); overflow: hidden; }
  .main { grid-area: main; overflow: auto; padding: 20px; }
</style>
