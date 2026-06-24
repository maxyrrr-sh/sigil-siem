<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { navigate } from '../lib/router.svelte';
  import type { Alert, Incident } from '../lib/types';
  import Badge from '../components/Badge.svelte';
  import States from '../components/States.svelte';
  import { fmtTime } from '../lib/format';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let events = $state(0);
  let alerts = $state<Alert[]>([]);
  let incidents = $state<Incident[]>([]);

  let topTechniques = $derived.by(() => {
    const counts = new Map<string, number>();
    for (const a of alerts) if (a.technique) counts.set(a.technique, (counts.get(a.technique) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  });

  async function load() {
    loading = true;
    error = null;
    try {
      const [c, al, inc] = await Promise.all([api.count(), api.alerts(), api.incidents()]);
      events = c.events;
      alerts = al.alerts;
      incidents = inc.incidents;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(load);
</script>

<div class="page">
  <div class="head"><h1>Overview</h1><button class="btn" onclick={load}>Refresh</button></div>
  <States {loading} {error} />

  {#if !loading && !error}
    <div class="kpis">
      <div class="card kpi"><div class="n">{events}</div><div class="muted">events</div></div>
      <div class="card kpi"><div class="n">{alerts.length}</div><div class="muted">alerts</div></div>
      <div class="card kpi"><div class="n">{incidents.length}</div><div class="muted">incidents</div></div>
      <div class="card kpi"><div class="n">{topTechniques[0]?.[0] ?? '—'}</div><div class="muted">top technique</div></div>
    </div>

    <div class="cols">
      <div class="card">
        <h2>Recent alerts</h2>
        <div class="scroll" style="max-height: 320px">
          <table>
            <thead><tr><th>rule</th><th>title</th><th>severity</th><th>ATT&CK</th></tr></thead>
            <tbody>
              {#each alerts.slice(0, 12) as a (a.events.join() + a.rule_id + a.ts)}
                <tr>
                  <td class="mono">{a.rule_id}</td>
                  <td>{a.title}</td>
                  <td><Badge severity={a.severity} /></td>
                  <td>{#if a.technique}<span class="pill">{a.technique}</span>{/if}</td>
                </tr>
              {/each}
              {#if alerts.length === 0}<tr><td colspan="4" class="faint">no alerts</td></tr>{/if}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <h2>Top incident</h2>
        {#if incidents[0]}
          {@const inc = incidents[0]}
          <div class="row" style="margin-bottom: 8px">
            <span class="tag">{inc.tactics.join(' → ')}</span>
            <span class="spacer"></span>
            <span class="muted">confidence {inc.confidence.toFixed(2)}</span>
          </div>
          <ol class="chain">
            {#each inc.chain as s (s.event_id)}
              <li><span class="tag">{s.tactic ?? '—'}</span> {s.label}
                {#if s.technique}<span class="pill">{s.technique}</span>{/if}</li>
            {/each}
          </ol>
          <button class="btn" onclick={() => navigate('/incidents')}>Open incidents →</button>
        {:else}
          <div class="faint">no incidents reconstructed yet</div>
        {/if}
        <div class="muted ts">updated {fmtTime(Date.now() * 1000)}</div>
      </div>
    </div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
  .kpi .n { font-size: 26px; font-weight: 600; color: var(--text-strong); }
  .cols { display: grid; grid-template-columns: 1.4fr 1fr; gap: 16px; }
  .chain { margin: 0 0 12px; padding-left: 18px; display: grid; gap: 4px; }
  .chain li { color: var(--text); }
  .ts { font-size: 11px; margin-top: 8px; }
  @media (max-width: 980px) { .kpis { grid-template-columns: repeat(2, 1fr); } .cols { grid-template-columns: 1fr; } }
</style>
