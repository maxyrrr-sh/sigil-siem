<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api } from '../lib/api';
  import type { AlertRecord, TriageStatus } from '../lib/types';
  import { can } from '../lib/auth.svelte';
  import Badge from '../components/Badge.svelte';
  import States from '../components/States.svelte';
  import { fmtTime } from '../lib/format';

  const STATUSES: TriageStatus[] = ['open', 'acknowledged', 'closed'];
  const editable = can('analyst');

  let loading = $state(true);
  let error = $state<string | null>(null);
  let records = $state<AlertRecord[]>([]);
  let technique = $state('');
  let sevFilter = $state('all');
  let statusFilter = $state('all');
  let selected = $state<Set<string>>(new Set());
  let expanded = $state<string | null>(null);
  let live = $state(true);
  let noteText = $state('');
  let es: EventSource | null = null;

  let shown = $derived(
    records.filter(
      (r) =>
        (sevFilter === 'all' || r.alert.severity === sevFilter) &&
        (statusFilter === 'all' || r.status === statusFilter),
    ),
  );

  function upsert(rec: AlertRecord) {
    const i = records.findIndex((r) => r.fingerprint === rec.fingerprint);
    if (i >= 0) records[i] = rec;
    else records = [rec, ...records];
  }

  async function setStatus(r: AlertRecord, s: TriageStatus) {
    if (!editable) return;
    try {
      const updated = (await api.patchAlert(r.fingerprint, { status: s })) as AlertRecord;
      upsert(updated);
    } catch (e) {
      error = (e as Error).message;
    }
  }
  async function setAssignee(r: AlertRecord, who: string) {
    if (!editable) return;
    try {
      const updated = (await api.patchAlert(r.fingerprint, { assignee: who })) as AlertRecord;
      upsert(updated);
    } catch (e) {
      error = (e as Error).message;
    }
  }
  async function addNote(r: AlertRecord) {
    if (!editable || !noteText.trim()) return;
    try {
      const updated = (await api.patchAlert(r.fingerprint, { note: noteText })) as AlertRecord;
      upsert(updated);
      noteText = '';
    } catch (e) {
      error = (e as Error).message;
    }
  }
  async function bulkStatus(s: TriageStatus) {
    if (!editable) return;
    const fps = shown.filter((r) => selected.has(r.fingerprint)).map((r) => r.fingerprint);
    if (fps.length === 0) return;
    try {
      await api.bulkPatchAlerts(fps, { status: s });
      selected = new Set();
      await load();
    } catch (e) {
      error = (e as Error).message;
    }
  }
  function toggle(fp: string) {
    const n = new Set(selected);
    n.has(fp) ? n.delete(fp) : n.add(fp);
    selected = n;
  }

  async function load() {
    loading = true;
    error = null;
    try {
      records = (await api.alerts(technique || undefined, 1000)).alerts;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  function connectStream() {
    es?.close();
    es = api.streamAlerts();
    es.onmessage = (ev) => {
      if (!live) return;
      try {
        upsert(JSON.parse(ev.data) as AlertRecord);
      } catch {
        /* ignore malformed frame */
      }
    };
    es.onerror = () => {
      /* browser auto-reconnects */
    };
  }

  onMount(() => {
    load();
    connectStream();
  });
  onDestroy(() => es?.close());
</script>

<div class="page">
  <div class="head">
    <h1>Alerts</h1>
    <div class="row filters">
      <input class="input flt" placeholder="technique (T1110.001)" bind:value={technique}
        onkeydown={(e) => e.key === 'Enter' && load()} />
      <select class="input sel" bind:value={sevFilter}>
        <option value="all">all severities</option>
        {#each ['critical','high','medium','low','informational'] as s (s)}<option value={s}>{s}</option>{/each}
      </select>
      <select class="input sel" bind:value={statusFilter}>
        <option value="all">all statuses</option>
        {#each STATUSES as s (s)}<option value={s}>{s}</option>{/each}
      </select>
      <label class="live"><input type="checkbox" bind:checked={live} /> live</label>
      <button class="btn" onclick={load}>Apply</button>
    </div>
  </div>

  {#if selected.size > 0 && editable}
    <div class="card bulk">
      <span>{selected.size} selected</span>
      <span class="spacer"></span>
      {#each STATUSES as s (s)}<button class="btn" onclick={() => bulkStatus(s)}>Mark {s}</button>{/each}
      <button class="btn" onclick={() => (selected = new Set())}>Clear</button>
    </div>
  {/if}

  <States {loading} {error}
    empty={!loading && !error && shown.length === 0}
    emptyText="No matching alerts." />

  {#if !loading && !error && shown.length}
    <div class="card">
      <h2>{shown.length} alerts</h2>
      <div class="scroll" style="max-height: 72vh">
        <table>
          <thead><tr><th></th><th>time</th><th>sev</th><th>rule</th><th>title</th><th>ATT&CK</th><th>assignee</th><th>status</th></tr></thead>
          <tbody>
            {#each shown as r (r.fingerprint)}
              <tr>
                <td><input type="checkbox" disabled={!editable} checked={selected.has(r.fingerprint)} onchange={() => toggle(r.fingerprint)} /></td>
                <td class="mono nowrap">{fmtTime(r.alert.ts)}</td>
                <td><Badge severity={r.alert.severity} /></td>
                <td class="mono">{r.alert.rule_id}</td>
                <td class="title" onclick={() => (expanded = expanded === r.fingerprint ? null : r.fingerprint)}>{r.alert.title}</td>
                <td>{#if r.alert.technique}<button class="pill linklike" onclick={() => { technique = r.alert.technique!; load(); }}>{r.alert.technique}</button>{/if}</td>
                <td class="mono asg">{r.assignee ?? '—'}</td>
                <td>
                  <select class="status status-{r.status}" disabled={!editable} value={r.status}
                    onchange={(e) => setStatus(r, (e.currentTarget as HTMLSelectElement).value as TriageStatus)}>
                    {#each STATUSES as s (s)}<option value={s}>{s}</option>{/each}
                  </select>
                </td>
              </tr>
              {#if expanded === r.fingerprint}
                <tr><td colspan="8"><div class="detail">
                  <b>matched events</b>
                  <div class="ids">{#each r.alert.events as id (id)}<code class="id">{id}</code>{/each}</div>
                  {#if editable}
                    <div class="row mt">
                      <input class="input asgn" placeholder="assignee" value={r.assignee ?? ''}
                        onkeydown={(e) => e.key === 'Enter' && setAssignee(r, (e.currentTarget as HTMLInputElement).value)} />
                      <input class="input notein" placeholder="add note… (Enter)" bind:value={noteText}
                        onkeydown={(e) => e.key === 'Enter' && addNote(r)} />
                    </div>
                  {/if}
                  {#if r.notes.length}
                    <div class="notes">{#each r.notes as n (n.ts)}<div class="note"><span class="who">{n.author}</span> {n.text} <span class="faint">{fmtTime(n.ts)}</span></div>{/each}</div>
                  {/if}
                </div></td></tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
  .filters { flex-wrap: wrap; }
  .flt { width: 200px; }
  .sel { width: auto; }
  .live { font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 5px; }
  .bulk { display: flex; align-items: center; gap: 8px; padding: 8px 16px; }
  .nowrap { white-space: nowrap; }
  .title { cursor: pointer; }
  .linklike { cursor: pointer; }
  .asg { color: var(--muted); }
  .status { background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 2px 6px; font: inherit; font-size: 12px; }
  .status-open { color: var(--sev-high); }
  .status-acknowledged { color: var(--sev-medium); }
  .status-closed { color: var(--faint); }
  .detail { padding: 4px 0; }
  .ids { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
  .id { font-size: 11px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; }
  .mt { margin-top: 8px; }
  .asgn { width: 160px; }
  .notein { width: 280px; }
  .notes { margin-top: 8px; display: grid; gap: 4px; }
  .note { font-size: 12px; color: var(--text); }
  .note .who { color: var(--text-strong); font-weight: 600; }
</style>
