<script lang="ts">
  import { api } from '../lib/api';
  import type { AnalyticsResponse, SigilEvent } from '../lib/types';
  import { className, fmtTime } from '../lib/format';
  import Badge from '../components/Badge.svelte';
  import States from '../components/States.svelte';

  type Mode = 'search' | 'sql' | 'dsl';
  let mode = $state<Mode>('search');
  let q = $state('');
  let loading = $state(false);
  let error = $state<string | null>(null);
  let events = $state<SigilEvent[]>([]);
  let analytics = $state<AnalyticsResponse | null>(null);
  let expanded = $state<string | null>(null);
  let ran = $state(false);

  const placeholders: Record<Mode, string> = {
    search: 'full-text over message / host / actor / target — empty = all events',
    sql: 'SELECT … FROM events …',
    dsl: 'search … | where … | stats count() by …',
  };
  const samples: Record<Mode, string[]> = {
    search: ['failed', 'shell.php', 'web01', '/etc/shadow'],
    sql: [
      'SELECT ocsf_class_name, count(*) AS n FROM events GROUP BY ocsf_class_name ORDER BY n DESC',
      'SELECT host, count(*) AS n FROM events GROUP BY host ORDER BY n DESC',
    ],
    dsl: ['search failed | stats count() as hits by host', 'where severity = high'],
  };

  // facet counts for the field sidebar (events mode)
  let facets = $derived.by(() => {
    const by = (f: (e: SigilEvent) => string | undefined) => {
      const m = new Map<string, number>();
      for (const e of events) {
        const v = f(e);
        if (v) m.set(v, (m.get(v) ?? 0) + 1);
      }
      return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    };
    return {
      class: by((e) => className(e.ocsf_class)),
      severity: by((e) => e.severity),
      host: by((e) => e.host?.id),
    };
  });

  async function run() {
    loading = true;
    error = null;
    ran = true;
    analytics = null;
    expanded = null;
    try {
      if (mode === 'search') {
        events = (await api.search(q, 200)).events;
      } else {
        events = [];
        analytics = mode === 'sql' ? await api.sql(q) : await api.query(q);
      }
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  function setMode(m: Mode) {
    mode = m;
    error = null;
  }
  function onKey(e: KeyboardEvent) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run();
  }
</script>

<div class="page">
  <div class="head"><h1>Search &amp; Investigate</h1></div>

  <div class="card bar">
    <div class="row">
      <div class="seg">
        <button class:active={mode === 'search'} onclick={() => setMode('search')}>Search</button>
        <button class:active={mode === 'sql'} onclick={() => setMode('sql')}>SQL</button>
        <button class:active={mode === 'dsl'} onclick={() => setMode('dsl')}>Pipe-DSL</button>
      </div>
      <span class="spacer"></span>
      <button class="btn primary" onclick={run} disabled={loading}>Run ⌘↵</button>
    </div>
    <textarea
      class="input"
      rows="2"
      placeholder={placeholders[mode]}
      bind:value={q}
      onkeydown={onKey}
    ></textarea>
    <div class="chips">
      {#each samples[mode] as s (s)}
        <button class="chip" onclick={() => { q = s; run(); }}>{s}</button>
      {/each}
    </div>
  </div>

  <States {loading} {error} />

  {#if !loading && !error && ran}
    {#if analytics}
      <div class="card">
        <h2>Result · {analytics.count} rows</h2>
        <div class="mono faint sql">{analytics.sql}</div>
        <div class="scroll">
          <table>
            <thead><tr>{#each analytics.columns as c (c)}<th>{c}</th>{/each}</tr></thead>
            <tbody>
              {#each analytics.rows as r, i (i)}
                <tr>{#each analytics.columns as c (c)}<td class="mono">{r[c] as any}</td>{/each}</tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    {:else}
      <div class="results">
        <div class="card events">
          <h2>{events.length} events</h2>
          <div class="scroll" style="max-height: 70vh">
            <table>
              <thead><tr><th>time</th><th>sev</th><th>class</th><th>host</th><th>actor</th><th>message</th></tr></thead>
              <tbody>
                {#each events as e (e.id)}
                  <tr class="ev" onclick={() => (expanded = expanded === e.id ? null : e.id)}>
                    <td class="mono nowrap">{fmtTime(e.ts)}</td>
                    <td><Badge severity={e.severity} /></td>
                    <td class="mono">{className(e.ocsf_class)}</td>
                    <td class="mono">{e.host?.id ?? ''}</td>
                    <td class="mono">{e.actor ? `${e.actor.kind}:${e.actor.id}` : ''}</td>
                    <td class="msg">{e.message}</td>
                  </tr>
                  {#if expanded === e.id}
                    <tr><td colspan="6"><pre class="json">{JSON.stringify(e, null, 2)}</pre></td></tr>
                  {/if}
                {/each}
                {#if events.length === 0}<tr><td colspan="6" class="faint">no matching events</td></tr>{/if}
              </tbody>
            </table>
          </div>
        </div>

        <div class="card fields">
          <h2>Fields</h2>
          {#each [['class', facets.class], ['severity', facets.severity], ['host', facets.host]] as [name, list] (name)}
            <div class="facet">
              <div class="facet-name">{name}</div>
              {#each list as [val, n] (val)}
                <button class="facet-row" onclick={() => { q = String(val); run(); }}>
                  <span class="facet-val">{val}</span><span class="facet-n">{n}</span>
                </button>
              {/each}
              {#if list.length === 0}<div class="faint sm">—</div>{/if}
            </div>
          {/each}
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .bar { display: grid; gap: 10px; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip { background: var(--surface-2); border: 1px solid var(--border); color: var(--muted); border-radius: 6px; padding: 3px 8px; cursor: pointer; font: inherit; font-size: 12px; }
  .chip:hover { color: var(--text-strong); border-color: var(--border-2); }
  .results { display: grid; grid-template-columns: 1fr 220px; gap: 16px; }
  .sql { margin-bottom: 10px; font-size: 12px; }
  .ev { cursor: pointer; }
  .msg { color: var(--text); }
  .nowrap { white-space: nowrap; }
  .json { margin: 0; padding: 10px; background: var(--bg); border-radius: 6px; font-size: 12px; color: var(--text); overflow: auto; }
  .facet { margin-bottom: 14px; }
  .facet-name { font-size: 11px; text-transform: uppercase; color: var(--faint); margin-bottom: 4px; }
  .facet-row { display: flex; width: 100%; justify-content: space-between; gap: 8px; background: transparent; border: 0; color: var(--text); padding: 3px 6px; border-radius: 4px; cursor: pointer; font: inherit; }
  .facet-row:hover { background: var(--surface-2); }
  .facet-val { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .facet-n { color: var(--muted); }
  .sm { font-size: 12px; }
  @media (max-width: 980px) { .results { grid-template-columns: 1fr; } }
</style>
