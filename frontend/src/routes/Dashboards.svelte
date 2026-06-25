<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { AnalyticsResponse } from '../lib/types';
  import BarChart from '../components/BarChart.svelte';
  import States from '../components/States.svelte';

  type Panel = { id: number; title: string; sql: string };
  const defaults: Panel[] = [
    { id: 1, title: 'Events by OCSF class', sql: 'SELECT ocsf_class_name, count(*) AS n FROM events GROUP BY ocsf_class_name ORDER BY n DESC' },
    { id: 2, title: 'Top hosts', sql: 'SELECT host, count(*) AS n FROM events GROUP BY host ORDER BY n DESC LIMIT 10' },
    { id: 3, title: 'Events by severity', sql: 'SELECT severity, count(*) AS n FROM events GROUP BY severity ORDER BY n DESC' },
    { id: 4, title: 'Total events', sql: 'SELECT count(*) AS events FROM events' },
  ];

  let panels = $state<Panel[]>(defaults);
  let results = $state<Record<number, AnalyticsResponse | { error: string }>>({});
  let loading = $state(true);

  async function loadDash() {
    try {
      const res = await api.savedList('dashboards');
      const obj = res.objects.find((o) => o.id === 'default');
      const body = obj?.body as { panels?: Panel[] } | undefined;
      if (body?.panels && Array.isArray(body.panels)) panels = body.panels;
    } catch {
      /* persistence off — use defaults */
    }
  }
  async function persistDash() {
    try {
      await api.savedUpdate('dashboards', 'default', 'default', { panels });
    } catch {
      /* best effort */
    }
  }

  function isBars(r: AnalyticsResponse): boolean {
    return r.columns.length >= 2 && r.rows.length > 1;
  }
  function isSingle(r: AnalyticsResponse): boolean {
    return r.rows.length === 1 && r.columns.length === 1;
  }
  function bars(r: AnalyticsResponse) {
    const lab = r.columns[0];
    const val = r.columns[r.columns.length - 1];
    return r.rows.map((row) => ({ label: String(row[lab] ?? ''), value: Number(row[val] ?? 0) }));
  }

  async function runPanel(p: Panel) {
    try {
      results[p.id] = await api.sql(p.sql);
    } catch (e) {
      results[p.id] = { error: (e as Error).message };
    }
  }
  async function runAll() {
    loading = true;
    await Promise.all(panels.map(runPanel));
    loading = false;
  }
  function addPanel() {
    const title = prompt('Panel title:');
    if (!title) return;
    const sql = prompt('SQL (over the `events` table):', 'SELECT host, count(*) AS n FROM events GROUP BY host');
    if (!sql) return;
    const p = { id: Date.now(), title, sql };
    panels = [...panels, p];
    persistDash();
    runPanel(p);
  }
  function removePanel(id: number) {
    panels = panels.filter((p) => p.id !== id);
    persistDash();
  }

  onMount(async () => {
    await loadDash();
    runAll();
  });
</script>

<div class="page">
  <div class="head">
    <h1>Dashboards</h1>
    <div class="row">
      <button class="btn" onclick={addPanel}>+ Panel</button>
      <button class="btn" onclick={runAll}>Refresh</button>
    </div>
  </div>

  <States loading={loading && Object.keys(results).length === 0} />

  <div class="panels">
    {#each panels as p (p.id)}
      {@const r = results[p.id]}
      <div class="card panel">
        <div class="prow"><h2>{p.title}</h2><span class="spacer"></span><button class="x" onclick={() => removePanel(p.id)} title="remove">×</button></div>
        {#if !r}
          <div class="faint sm">loading…</div>
        {:else if 'error' in r}
          <div class="errbox">{r.error}</div>
        {:else if isSingle(r)}
          <div class="single">{r.rows[0][r.columns[0]] as any}</div>
          <div class="faint sm">{r.columns[0]}</div>
        {:else if isBars(r)}
          <BarChart data={bars(r)} />
        {:else}
          <div class="scroll"><table>
            <thead><tr>{#each r.columns as c (c)}<th>{c}</th>{/each}</tr></thead>
            <tbody>{#each r.rows as row, i (i)}<tr>{#each r.columns as c (c)}<td class="mono">{row[c] as any}</td>{/each}</tr>{/each}</tbody>
          </table></div>
        {/if}
        <div class="sql mono faint">{p.sql}</div>
      </div>
    {/each}
  </div>
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .panels { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 16px; }
  .panel { display: grid; gap: 8px; align-content: start; }
  .prow { display: flex; align-items: center; }
  .x { background: transparent; border: 0; color: var(--faint); cursor: pointer; font-size: 18px; line-height: 1; }
  .x:hover { color: var(--sev-high); }
  .single { font-size: 38px; font-weight: 600; color: var(--text-strong); }
  .sm { font-size: 12px; }
  .sql { font-size: 11px; margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
