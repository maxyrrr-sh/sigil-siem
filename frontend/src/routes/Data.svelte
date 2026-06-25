<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { CountResponse, SystemInfo } from '../lib/types';
  import States from '../components/States.svelte';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let sys = $state<SystemInfo | null>(null);
  let count = $state<CountResponse | null>(null);

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
  <div class="head"><h1>Data management</h1><button class="btn" onclick={load}>Refresh</button></div>
  <States {loading} {error} />

  {#if !loading && !error && sys}
    <div class="tiers">
      <div class="card tier"><div class="tn">hot</div><div class="td">Tantivy · full-text</div><div class="tr">{sys.retention_hot}</div><div class="faint sm mono">{sys.index_path}</div></div>
      <div class="arrow">→</div>
      <div class="card tier"><div class="tn">warm</div><div class="td">local disk</div><div class="tr">{sys.retention_warm}</div><div class="faint sm">migration: planned</div></div>
      <div class="arrow">→</div>
      <div class="card tier"><div class="tn">cold</div><div class="td">Parquet · DataFusion</div><div class="tr">{sys.retention_cold}</div><div class="faint sm mono">{sys.cold_path}</div></div>
    </div>

    <div class="cols">
      <div class="card">
        <h2>Inputs / sources · {sys.sources.length}</h2>
        <table>
          <thead><tr><th>id</th><th>kind</th><th>codec</th></tr></thead>
          <tbody>
            {#each sys.sources as s (s.id)}<tr><td class="mono">{s.id}</td><td>{s.kind}</td><td>{s.codec}</td></tr>{/each}
            {#if sys.sources.length === 0}<tr><td colspan="3" class="faint">no inputs configured</td></tr>{/if}
          </tbody>
        </table>
      </div>

      <div class="card">
        <h2>Pipelines · {sys.pipelines.length}</h2>
        {#each sys.pipelines as p (p.id)}
          <div class="pipe">
            <span class="mono pid">{p.id}</span>
            <span class="flow">[{p.from.join(', ')}] → {p.route.join(', ')}</span>
          </div>
        {/each}
        {#if sys.pipelines.length === 0}<div class="faint">no pipelines</div>{/if}
      </div>
    </div>

    <div class="card stat">
      <div><b>{count?.events ?? '–'}</b> events indexed · <b>{count?.alerts ?? '–'}</b> alerts · <b>{sys.rule_count}</b> rules</div>
      <div class="muted sm">Segment catalog + normalization preview + retro-hunt are the next data-mgmt items (FRONTEND.md §5.11).</div>
    </div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .tiers { display: flex; align-items: stretch; gap: 12px; }
  .tier { flex: 1; display: grid; gap: 4px; }
  .tier .tn { font-size: 14px; font-weight: 600; color: var(--text-strong); text-transform: uppercase; }
  .tier .td { color: var(--muted); font-size: 12px; }
  .tier .tr { color: var(--accent-2); font-family: var(--mono); }
  .arrow { display: flex; align-items: center; color: var(--faint); font-size: 20px; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .pipe { display: flex; gap: 12px; padding: 4px 0; border-bottom: 1px solid var(--border); }
  .pid { color: var(--text-strong); }
  .flow { color: var(--muted); font-size: 13px; }
  .stat b { color: var(--text-strong); }
  .sm { font-size: 12px; margin-top: 6px; }
  @media (max-width: 900px) { .cols { grid-template-columns: 1fr; } .tiers { flex-direction: column; } .arrow { transform: rotate(90deg); } }
</style>
