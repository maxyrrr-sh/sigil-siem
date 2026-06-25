<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { CountResponse, SystemInfo } from '../lib/types';
  import States from '../components/States.svelte';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let sys = $state<SystemInfo | null>(null);
  let count = $state<CountResponse | null>(null);

  const ALL_ROLES = ['ingest', 'index', 'correlate', 'query', 'coordinator'];

  async function load() {
    loading = true;
    error = null;
    try {
      [sys, count] = await Promise.all([api.system(), api.count()]);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(load);
</script>

<div class="page">
  <div class="head"><h1>Cluster &amp; health</h1><button class="btn" onclick={load}>Refresh</button></div>
  <States {loading} {error} />

  {#if !loading && !error && sys}
    <div class="grid3">
      <div class="card"><h2>Roles (this node)</h2>
        <div class="roles">
          {#each ALL_ROLES as r (r)}
            <span class="role" class:on={sys.roles.includes(r)}>{r}</span>
          {/each}
        </div>
        <div class="muted sm">{sys.roles.length === ALL_ROLES.length ? 'monolith — all roles in-process' : 'partial role set'}</div>
      </div>
      <div class="card kpi"><div class="n">{sys.transport}</div><div class="muted">transport</div></div>
      <div class="card kpi"><div class="n">{count?.events ?? '–'}</div><div class="muted">events indexed</div></div>
    </div>

    <div class="card">
      <h2>Shard map · {sys.shards} shards · replication {sys.replication}</h2>
      <div class="nodes">
        {#each sys.nodes as node, i (node)}
          <div class="node">
            <div class="node-name">{node}{#if i === 0}<span class="lead">primary-ish</span>{/if}</div>
            <div class="shardbar">
              {#each Array(Math.min(sys.shards, 16)) as _, s (s)}
                <span class="sh" class:mine={s % sys.nodes.length === i}></span>
              {/each}
            </div>
          </div>
        {/each}
      </div>
      <div class="muted sm">Placement = time+hash sharding around the node ring (DESIGN §4.3). Live multi-node consensus (Raft) is the documented next step.</div>
    </div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .grid3 { display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 16px; }
  .kpi .n { font-size: 24px; font-weight: 600; color: var(--text-strong); }
  .roles { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; }
  .role { border: 1px solid var(--border); border-radius: 6px; padding: 3px 10px; color: var(--faint); font-size: 12px; }
  .role.on { color: var(--ok); border-color: var(--ok); background: rgba(79,209,139,.08); }
  .nodes { display: grid; gap: 10px; }
  .node { display: grid; grid-template-columns: 160px 1fr; gap: 12px; align-items: center; }
  .node-name { font-family: var(--mono); color: var(--text); }
  .lead { margin-left: 8px; font-size: 10px; color: var(--accent-2); }
  .shardbar { display: flex; gap: 3px; flex-wrap: wrap; }
  .sh { width: 14px; height: 14px; border-radius: 3px; background: var(--bg); border: 1px solid var(--border); }
  .sh.mine { background: var(--accent); opacity: 0.7; border-color: var(--accent); }
  .sm { font-size: 12px; margin-top: 8px; }
  @media (max-width: 900px) { .grid3 { grid-template-columns: 1fr; } }
</style>
