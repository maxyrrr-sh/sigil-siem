<script lang="ts">
  import { onMount } from 'svelte';
  import { router } from './lib/router.svelte';
  import { auth, bootstrap } from './lib/auth.svelte';
  import Topbar from './components/Topbar.svelte';
  import Sidebar from './components/Sidebar.svelte';
  import Login from './routes/Login.svelte';
  import Overview from './routes/Overview.svelte';
  import Search from './routes/Search.svelte';
  import Alerts from './routes/Alerts.svelte';
  import Incidents from './routes/Incidents.svelte';
  import Detections from './routes/Detections.svelte';
  import Attack from './routes/Attack.svelte';
  import Dashboards from './routes/Dashboards.svelte';
  import Hunt from './routes/Hunt.svelte';
  import Entities from './routes/Entities.svelte';
  import Data from './routes/Data.svelte';
  import Cluster from './routes/Cluster.svelte';
  import Plugins from './routes/Plugins.svelte';
  import Agents from './routes/Agents.svelte';
  import Configuration from './routes/Configuration.svelte';
  import Eval from './routes/Eval.svelte';
  import Admin from './routes/Admin.svelte';
  import Placeholder from './routes/Placeholder.svelte';

  onMount(bootstrap);
  let authed = $derived(auth.ready && (!auth.enabled || auth.user !== null));
</script>

{#if !auth.ready}
  <div class="boot">Loading…</div>
{:else if !authed}
  <Login />
{:else}
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
    {:else if router.path === '/detections'}
      <Detections />
    {:else if router.path === '/attack'}
      <Attack />
    {:else if router.path === '/dashboards'}
      <Dashboards />
    {:else if router.path === '/hunt'}
      <Hunt />
    {:else if router.path === '/entities'}
      <Entities />
    {:else if router.path === '/data'}
      <Data />
    {:else if router.path === '/cluster'}
      <Cluster />
    {:else if router.path === '/plugins'}
      <Plugins />
    {:else if router.path === '/agents'}
      <Agents />
    {:else if router.path === '/config'}
      <Configuration />
    {:else if router.path === '/eval'}
      <Eval />
    {:else if router.path === '/admin'}
      <Admin />
    {:else}
      <Placeholder title="Not found" phase="404" blurb={`No view for ${router.path}.`} />
    {/if}
  </main>
</div>
{/if}

<style>
  .boot { display: grid; place-items: center; height: 100vh; color: var(--muted); }
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
