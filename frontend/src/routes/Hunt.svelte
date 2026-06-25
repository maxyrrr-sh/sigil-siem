<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { AnalyticsResponse } from '../lib/types';

  type Cell = {
    id: number;
    type: 'md' | 'query';
    text: string;
    mode?: 'sql' | 'dsl';
    result?: AnalyticsResponse | { error: string };
    editing?: boolean;
  };

  const seed: Cell[] = [
    { id: 1, type: 'md', text: '# Threat hunt\nNotes + runnable query cells. Saved locally.' },
    { id: 2, type: 'query', mode: 'dsl', text: 'search failed | stats count() as hits by host' },
  ];
  let cells = $state<Cell[]>(seed);

  async function loadNb() {
    try {
      const res = await api.savedList('hunts');
      const obj = res.objects.find((o) => o.id === 'default');
      const body = obj?.body as { cells?: Cell[] } | undefined;
      if (body?.cells && Array.isArray(body.cells)) cells = body.cells;
    } catch {
      /* persistence off — use seed */
    }
  }
  async function persist() {
    const clean = cells.map(({ result, editing, ...c }) => c);
    try {
      await api.savedUpdate('hunts', 'default', 'default', { cells: clean });
    } catch {
      /* best effort */
    }
  }

  onMount(loadNb);
  function add(type: 'md' | 'query') {
    cells = [...cells, { id: Date.now(), type, text: '', mode: 'sql', editing: true }];
    persist();
  }
  function remove(id: number) {
    cells = cells.filter((c) => c.id !== id);
    persist();
  }
  async function runCell(c: Cell) {
    try {
      c.result = c.mode === 'dsl' ? await api.query(c.text) : await api.sql(c.text);
    } catch (e) {
      c.result = { error: (e as Error).message };
    }
    cells = cells;
  }

  // tiny markdown: # heading, blank line = paragraph break
  function md(text: string): string {
    return text
      .split('\n')
      .map((l) =>
        l.startsWith('# ') ? `<h3>${esc(l.slice(2))}</h3>` : l.trim() === '' ? '' : `<p>${esc(l)}</p>`,
      )
      .join('');
  }
  function esc(s: string): string {
    return s.replace(/[&<>]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[m]!);
  }
</script>

<div class="page">
  <div class="head">
    <h1>Threat hunting</h1>
    <div class="row">
      <button class="btn" onclick={() => add('md')}>+ Note</button>
      <button class="btn" onclick={() => add('query')}>+ Query</button>
    </div>
  </div>

  <div class="nb">
    {#each cells as c (c.id)}
      <div class="card cell">
        <div class="crow">
          <span class="ctype">{c.type === 'md' ? 'note' : `query · ${c.mode}`}</span>
          <span class="spacer"></span>
          {#if c.type === 'query'}
            <div class="seg sm">
              <button class:active={c.mode === 'sql'} onclick={() => { c.mode = 'sql'; cells = cells; }}>SQL</button>
              <button class:active={c.mode === 'dsl'} onclick={() => { c.mode = 'dsl'; cells = cells; }}>DSL</button>
            </div>
            <button class="btn sm" onclick={() => runCell(c)}>Run</button>
          {/if}
          <button class="btn sm" onclick={() => { c.editing = !c.editing; cells = cells; if (!c.editing) persist(); }}>{c.editing ? 'Done' : 'Edit'}</button>
          <button class="x" onclick={() => remove(c.id)}>×</button>
        </div>

        {#if c.editing}
          <textarea class="input" rows={c.type === 'md' ? 3 : 2} bind:value={c.text} onblur={persist}></textarea>
        {:else if c.type === 'md'}
          <div class="md">{@html md(c.text)}</div>
        {:else}
          <div class="mono qtext">{c.text}</div>
        {/if}

        {#if c.type === 'query' && c.result}
          {#if 'error' in c.result}
            <div class="errbox">{c.result.error}</div>
          {:else}
            <div class="scroll"><table>
              <thead><tr>{#each c.result.columns as col (col)}<th>{col}</th>{/each}</tr></thead>
              <tbody>{#each c.result.rows as row, i (i)}<tr>{#each c.result.columns as col (col)}<td class="mono">{row[col] as any}</td>{/each}</tr>{/each}</tbody>
            </table></div>
            <div class="faint sm">{c.result.count} rows</div>
          {/if}
        {/if}
      </div>
    {/each}
  </div>
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .nb { display: grid; gap: 12px; max-width: 1000px; }
  .cell { display: grid; gap: 8px; }
  .crow { display: flex; align-items: center; gap: 8px; }
  .ctype { font-size: 11px; text-transform: uppercase; color: var(--faint); letter-spacing: 0.04em; }
  .seg.sm button { padding: 2px 8px; font-size: 12px; }
  .btn.sm { padding: 3px 8px; font-size: 12px; }
  .x { background: transparent; border: 0; color: var(--faint); cursor: pointer; font-size: 18px; }
  .x:hover { color: var(--sev-high); }
  .md :global(h3) { margin: 4px 0; }
  .md :global(p) { margin: 4px 0; color: var(--text); }
  .qtext { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; }
  .sm { font-size: 12px; }
</style>
