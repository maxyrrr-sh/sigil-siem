<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { Incident } from '../lib/types';
  import States from '../components/States.svelte';
  import AttackGraph from '../components/AttackGraph.svelte';
  import { confidenceLabel, fmtTime } from '../lib/format';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let incidents = $state<Incident[]>([]);
  let selectedId = $state<number | null>(null);
  let stageIdx = $state(0);

  let selected = $derived(incidents.find((i) => i.id === selectedId) ?? incidents[0] ?? null);
  let stage = $derived(selected?.chain[stageIdx] ?? null);

  // unique entities involved, parsed from the chain + the "why" explanations.
  let entities = $derived.by(() => {
    if (!selected) return [] as string[];
    const set = new Set<string>();
    const re = /\b(host|user|ip|process|file|url):([^\s,;)]+)/g;
    for (const w of selected.explanation) {
      let m: RegExpExecArray | null;
      while ((m = re.exec(w))) set.add(`${m[1]}:${m[2]}`);
    }
    for (const s of selected.chain) {
      const m = s.label.match(/(\w+):(\S+)/);
      if (m) set.add(`${m[1]}:${m[2]}`);
    }
    return [...set].sort();
  });

  function pick(id: number) {
    selectedId = id;
    stageIdx = 0;
  }

  async function load() {
    loading = true;
    error = null;
    try {
      incidents = (await api.incidents()).incidents;
      if (incidents[0]) selectedId = incidents[0].id;
      stageIdx = 0;
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
          <button class="inc" class:active={selected?.id === inc.id} onclick={() => pick(inc.id)}>
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
              <h2 style="margin:0">Incident #{selected.id} · attack graph</h2>
              <span class="spacer"></span>
              <span class="conf conf-{confidenceLabel(selected.confidence)}">confidence {selected.confidence.toFixed(2)}</span>
            </div>
            <div class="tactics">{selected.tactics.join('  →  ')}</div>
            <AttackGraph incident={selected} selected={stageIdx} onselect={(i) => (stageIdx = i)} />
            {#if stage}
              <div class="stagebox">
                <b>Stage {stageIdx + 1}/{selected.chain.length}</b> · <span class="tag">{stage.tactic ?? '—'}</span>
                {#if stage.technique}<span class="pill">{stage.technique}</span>{/if}
                <span class="muted"> · {stage.label} · anomaly {stage.anomaly.toFixed(2)}</span>
                <code class="evid faint">{stage.event_id.slice(0, 12)}</code>
              </div>
            {/if}
          </div>

          <div class="card">
            <h2>Involved entities</h2>
            <div class="ents">
              {#each entities as e (e)}<span class="pill ent">{e}</span>{/each}
              {#if entities.length === 0}<span class="faint">—</span>{/if}
            </div>
          </div>

          <div class="cols">
            <div class="card">
              <h2>Timeline</h2>
              <ol class="timeline">
                {#each selected.chain as s, i (s.event_id)}
                  <li class:cur={i === stageIdx}>
                    <span class="t mono">{fmtTime(s.ts)}</span>
                    <span class="dot"></span>
                    <button class="line" onclick={() => (stageIdx = i)}>
                      <span class="tag">{s.tactic ?? '—'}</span> {s.label}
                      {#if s.technique}<span class="pill">{s.technique}</span>{/if}
                    </button>
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
  .stagebox { margin-top: 8px; padding: 8px 10px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; font-size: 13px; }
  .evid { margin-left: 8px; font-size: 11px; }
  .ents { display: flex; flex-wrap: wrap; gap: 6px; }
  .ent { font-family: var(--mono); }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .timeline { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; }
  .timeline li { display: grid; grid-template-columns: 130px 14px 1fr; align-items: center; padding: 2px 0; }
  .timeline .t { color: var(--faint); font-size: 11px; }
  .timeline .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--border-2); justify-self: center; }
  .timeline li.cur .dot { background: var(--accent); }
  .timeline .line { background: transparent; border: 0; color: var(--text); text-align: left; cursor: pointer; font: inherit; padding: 4px 6px; border-radius: 4px; }
  .timeline li.cur .line { background: var(--surface-2); }
  .why { margin: 0; padding-left: 18px; display: grid; gap: 6px; }
  .conf { font-size: 12px; color: var(--muted); }
  .conf-high { color: var(--sev-high); }
  .conf-medium { color: var(--sev-medium); }
  @media (max-width: 1100px) { .layout { grid-template-columns: 1fr; } .cols { grid-template-columns: 1fr; } }
</style>
