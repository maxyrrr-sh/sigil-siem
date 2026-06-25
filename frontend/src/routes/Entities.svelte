<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { EntityRef, SigilEvent } from '../lib/types';
  import { fmtTime } from '../lib/format';
  import States from '../components/States.svelte';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let events = $state<SigilEvent[]>([]);
  let selected = $state<string | null>(null);
  let filter = $state('');

  const key = (e: EntityRef) => `${e.kind}:${e.id}`;
  function entitiesOf(ev: SigilEvent): string[] {
    return [ev.host, ev.actor, ev.target].filter(Boolean).map((e) => key(e as EntityRef));
  }

  // all entities ranked by event count
  let ranked = $derived.by(() => {
    const m = new Map<string, number>();
    for (const ev of events) for (const k of entitiesOf(ev)) m.set(k, (m.get(k) ?? 0) + 1);
    return [...m.entries()]
      .filter(([k]) => !filter || k.toLowerCase().includes(filter.toLowerCase()))
      .sort((a, b) => b[1] - a[1]);
  });

  let related = $derived(selected ? events.filter((e) => entitiesOf(e).includes(selected!)) : []);
  let neighbors = $derived.by(() => {
    if (!selected) return [] as [string, number][];
    const m = new Map<string, number>();
    for (const e of related) for (const k of entitiesOf(e)) if (k !== selected) m.set(k, (m.get(k) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  });

  async function load() {
    loading = true;
    error = null;
    try {
      events = (await api.search('', 1000)).events;
      selected = ranked[0]?.[0] ?? null;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(load);
</script>

<div class="page">
  <div class="head">
    <h1>Entities</h1>
    <div class="row"><input class="input flt" placeholder="filter…" bind:value={filter} /><button class="btn" onclick={load}>Refresh</button></div>
  </div>

  <States {loading} {error}
    empty={!loading && !error && ranked.length === 0}
    emptyText="No entities yet — ingest some events." />

  {#if !loading && !error && ranked.length}
    <div class="layout">
      <div class="card list">
        <h2>{ranked.length} entities</h2>
        <div class="scroll" style="max-height: 70vh">
          {#each ranked as [k, n] (k)}
            <button class="ent" class:active={selected === k} onclick={() => (selected = k)}>
              <span class="kind">{k.split(':')[0]}</span>
              <span class="id">{k.slice(k.indexOf(':') + 1)}</span>
              <span class="n">{n}</span>
            </button>
          {/each}
        </div>
      </div>

      {#if selected}
        <div class="detail">
          <div class="card">
            <h2>{selected}</h2>
            <div class="muted">{related.length} events · {neighbors.length} connected entities</div>
            <div class="nbs">
              {#each neighbors.slice(0, 16) as [k, n] (k)}
                <button class="pill nb" onclick={() => (selected = k)}>{k} <span class="nbn">{n}</span></button>
              {/each}
            </div>
          </div>
          <div class="card">
            <h2>Activity</h2>
            <div class="scroll" style="max-height: 56vh">
              <table>
                <thead><tr><th>time</th><th>class</th><th>message</th></tr></thead>
                <tbody>
                  {#each related as e (e.id)}
                    <tr><td class="mono nowrap">{fmtTime(e.ts)}</td>
                      <td class="mono">{typeof e.ocsf_class === 'string' ? e.ocsf_class : Object.keys(e.ocsf_class)[0]}</td>
                      <td>{e.message}</td></tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .flt { width: 200px; }
  .layout { display: grid; grid-template-columns: 280px 1fr; gap: 16px; align-items: start; }
  .list { display: grid; gap: 4px; }
  .ent { display: grid; grid-template-columns: auto 1fr auto; gap: 8px; align-items: center; background: transparent; border: 0; color: var(--text); padding: 5px 8px; border-radius: 6px; cursor: pointer; text-align: left; }
  .ent:hover { background: var(--surface-2); }
  .ent.active { background: var(--surface-2); box-shadow: inset 2px 0 0 var(--accent); }
  .kind { font-size: 10px; text-transform: uppercase; color: var(--faint); }
  .id { font-family: var(--mono); font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .n { color: var(--muted); font-size: 12px; }
  .detail { display: grid; gap: 16px; }
  .nbs { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
  .nb { font-family: var(--mono); cursor: pointer; }
  .nbn { color: var(--muted); }
  .nowrap { white-space: nowrap; }
  @media (max-width: 1000px) { .layout { grid-template-columns: 1fr; } }
</style>
