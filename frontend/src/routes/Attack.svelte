<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { AlertRecord, RuleInfo } from '../lib/types';
  import { tacticFor } from '../lib/attack';
  import States from '../components/States.svelte';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let rules = $state<RuleInfo[]>([]);
  let alerts = $state<AlertRecord[]>([]);

  type Cell = { technique: string; covered: boolean; observed: number };

  // tactic → techniques (union of rule-covered and alert-observed)
  let matrix = $derived.by(() => {
    const observed = new Map<string, number>();
    for (const r of alerts) if (r.alert.technique) observed.set(r.alert.technique, (observed.get(r.alert.technique) ?? 0) + 1);
    const covered = new Set(rules.map((r) => r.technique).filter(Boolean) as string[]);

    const byTactic = new Map<string, Map<string, Cell>>();
    const add = (technique: string) => {
      const t = tacticFor(technique);
      if (!byTactic.has(t)) byTactic.set(t, new Map());
      const m = byTactic.get(t)!;
      if (!m.has(technique))
        m.set(technique, { technique, covered: covered.has(technique), observed: observed.get(technique) ?? 0 });
    };
    covered.forEach(add);
    observed.forEach((_n, t) => add(t));

    return [...byTactic.entries()]
      .map(([tactic, m]) => ({ tactic, cells: [...m.values()].sort((a, b) => a.technique.localeCompare(b.technique)) }))
      .sort((a, b) => a.tactic.localeCompare(b.tactic));
  });

  async function load() {
    loading = true;
    error = null;
    try {
      const [r, a] = await Promise.all([api.rules(), api.alerts(undefined, 1000)]);
      rules = r.rules;
      alerts = a.alerts;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(load);

  function heat(c: Cell): string {
    if (c.observed > 0) return 'observed';
    if (c.covered) return 'covered';
    return 'gap';
  }
</script>

<div class="page">
  <div class="head">
    <h1>ATT&amp;CK coverage</h1>
    <div class="legend">
      <span class="sw observed"></span> observed
      <span class="sw covered"></span> rule coverage
      <span class="sw gap"></span> gap
    </div>
  </div>

  <States {loading} {error}
    empty={!loading && !error && matrix.length === 0}
    emptyText="No techniques yet — load rules and ingest some data." />

  {#if !loading && !error && matrix.length}
    <div class="matrix scroll">
      {#each matrix as col (col.tactic)}
        <div class="col">
          <div class="col-head">{col.tactic}</div>
          {#each col.cells as c (c.technique)}
            <div class="cell {heat(c)}" title={`${c.technique} · ${c.observed} alerts · ${c.covered ? 'rule' : 'no rule'}`}>
              <span class="t">{c.technique}</span>
              {#if c.observed > 0}<span class="n">{c.observed}</span>{/if}
            </div>
          {/each}
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .legend { font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 6px; }
  .sw { width: 12px; height: 12px; border-radius: 3px; display: inline-block; margin-left: 10px; border: 1px solid var(--border); }
  .matrix { display: flex; gap: 12px; align-items: flex-start; padding-bottom: 8px; }
  .col { min-width: 160px; display: grid; gap: 6px; }
  .col-head { font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--tactic); padding-bottom: 4px; border-bottom: 1px solid var(--border); }
  .cell { display: flex; align-items: center; justify-content: space-between; gap: 6px; padding: 6px 8px; border-radius: 6px; border: 1px solid var(--border); font-family: var(--mono); font-size: 12px; }
  .cell .n { font-size: 11px; color: var(--bg); background: var(--sev-high); border-radius: 8px; padding: 0 6px; }
  .observed { background: rgba(255,138,76,.16); border-color: var(--sev-high); color: var(--text-strong); }
  .covered { background: var(--surface-2); border-color: var(--border-2); color: var(--text); }
  .gap { color: var(--faint); border-style: dashed; }
  .sw.observed { background: rgba(255,138,76,.6); }
  .sw.covered { background: var(--surface-2); }
  .sw.gap { background: transparent; border-style: dashed; }
</style>
