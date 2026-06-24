<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { Incident } from '../lib/types';
  import States from '../components/States.svelte';
  import AttackGraph from '../components/AttackGraph.svelte';
  import { confidenceLabel } from '../lib/format';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let incidents = $state<Incident[]>([]);
  let selectedId = $state<number | null>(null);

  let selected = $derived(incidents.find((i) => i.id === selectedId) ?? incidents[0] ?? null);

  async function load() {
    loading = true;
    error = null;
    try {
      incidents = (await api.incidents()).incidents;
      if (incidents[0]) selectedId = incidents[0].id;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(load);
</script>

<div class="page">
  <div class="head"><h1>Incidents</h1><button class="btn" onclick={load}>Refresh</button></div>

  <States {loading} {error}
    empty={!loading && !error && incidents.length === 0}
    emptyText="No incidents reconstructed. Ingest a multi-stage scenario (e.g. seeds/) and they appear here." />

  {#if !loading && !error && incidents.length}
    <div class="layout">
      <div class="card list">
        <h2>{incidents.length} incidents</h2>
        {#each incidents as inc (inc.id)}
          <button class="inc" class:active={selected?.id === inc.id} onclick={() => (selectedId = inc.id)}>
            <div class="row">
              <span class="tag">{inc.tactics.join(' → ')}</span>
              <span class="spacer"></span>
              <span class="conf conf-{confidenceLabel(inc.confidence)}">{inc.confidence.toFixed(2)}</span>
            </div>
            <div class="meta">{inc.chain.length} stages · {inc.events.length} events</div>
            <div class="techs">{#each inc.techniques as t (t)}<span class="pill">{t}</span>{/each}</div>
          </button>
        {/each}
      </div>

      {#if selected}
        <div class="detail">
          <div class="card">
            <div class="row">
              <h2 style="margin:0">Incident #{selected.id} · reconstructed attack graph</h2>
              <span class="spacer"></span>
              <span class="conf conf-{confidenceLabel(selected.confidence)}">confidence {selected.confidence.toFixed(2)}</span>
            </div>
            <div class="tactics">{selected.tactics.join('  →  ')}</div>
            <AttackGraph incident={selected} />
          </div>

          <div class="cols">
            <div class="card">
              <h2>Kill-chain</h2>
              <ol class="chain">
                {#each selected.chain as s (s.event_id)}
                  <li>
                    <span class="tag">{s.tactic ?? '—'}</span> {s.label}
                    {#if s.technique}<span class="pill">{s.technique}</span>{/if}
                    <code class="evid faint">{s.event_id.slice(0, 8)}</code>
                  </li>
                {/each}
              </ol>
            </div>
            <div class="card">
              <h2>Why (contributing edges)</h2>
              <ul class="why">
                {#each selected.explanation as w (w)}<li>{w}</li>{/each}
                {#if selected.explanation.length === 0}<li class="faint">single-stage incident</li>{/if}
              </ul>
            </div>
          </div>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .layout { display: grid; grid-template-columns: 300px 1fr; gap: 16px; align-items: start; }
  .list { display: grid; gap: 8px; align-content: start; }
  .inc { text-align: left; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px; cursor: pointer; color: var(--text); display: grid; gap: 6px; }
  .inc:hover { border-color: var(--border-2); }
  .inc.active { border-color: var(--accent); box-shadow: inset 2px 0 0 var(--accent); }
  .meta { font-size: 12px; color: var(--muted); }
  .techs { display: flex; flex-wrap: wrap; gap: 4px; }
  .detail { display: grid; gap: 16px; }
  .tactics { color: var(--tactic); text-transform: uppercase; letter-spacing: 0.04em; font-size: 11px; margin: 8px 0 4px; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .chain { margin: 0; padding-left: 18px; display: grid; gap: 6px; }
  .why { margin: 0; padding-left: 18px; display: grid; gap: 6px; }
  .why li { color: var(--text); }
  .evid { margin-left: 6px; font-size: 11px; }
  .conf { font-size: 12px; color: var(--muted); }
  .conf-high { color: var(--sev-high); }
  .conf-medium { color: var(--sev-medium); }
  @media (max-width: 1100px) { .layout { grid-template-columns: 1fr; } .cols { grid-template-columns: 1fr; } }
</style>
