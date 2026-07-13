<script lang="ts">
  import { router, navigate } from '../lib/router.svelte';

  type Item = { label: string; path: string; ready?: boolean };
  type Group = { name: string; items: Item[] };

  const groups: Group[] = [
    {
      name: 'Investigate',
      items: [
        { label: 'Overview', path: '/', ready: true },
        { label: 'Search', path: '/search', ready: true },
        { label: 'Alerts', path: '/alerts', ready: true },
        { label: 'Incidents', path: '/incidents', ready: true },
      ],
    },
    {
      name: 'Detect',
      items: [
        { label: 'Detections', path: '/detections', ready: true },
        { label: 'ATT&CK coverage', path: '/attack', ready: true },
      ],
    },
    {
      name: 'Explore',
      items: [
        { label: 'Dashboards', path: '/dashboards', ready: true },
        { label: 'Hunting', path: '/hunt', ready: true },
        { label: 'Entities', path: '/entities', ready: true },
      ],
    },
    {
      name: 'Respond',
      items: [
        { label: 'Agents (EDR)', path: '/agents', ready: true },
      ],
    },
    {
      name: 'Operate',
      items: [
        { label: 'Data', path: '/data', ready: true },
        { label: 'Cluster', path: '/cluster', ready: true },
        { label: 'Plugins', path: '/plugins', ready: true },
        { label: 'Evaluation', path: '/eval', ready: true },
        { label: 'Admin', path: '/admin', ready: true },
      ],
    },
  ];
</script>

<nav class="side">
  {#each groups as group (group.name)}
    <div class="group">{group.name}</div>
    {#each group.items as item (item.path)}
      <button
        class="nav"
        class:active={router.path === item.path}
        onclick={() => navigate(item.path)}
      >
        <span>{item.label}</span>
        {#if !item.ready}<span class="soon">soon</span>{/if}
      </button>
    {/each}
  {/each}
</nav>

<style>
  .side { padding: 8px 8px 24px; overflow-y: auto; }
  .group {
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--faint); padding: 14px 10px 4px;
  }
  .nav {
    display: flex; align-items: center; width: 100%; gap: 8px;
    background: transparent; border: 0; color: var(--muted);
    padding: 6px 10px; border-radius: 6px; cursor: pointer; font: inherit; text-align: left;
  }
  .nav:hover { background: var(--surface-2); color: var(--text); }
  .nav.active { background: var(--surface-2); color: var(--text-strong); box-shadow: inset 2px 0 0 var(--accent); }
  .soon { margin-left: auto; font-size: 9px; color: var(--faint); border: 1px solid var(--border); border-radius: 8px; padding: 0 5px; }
</style>
