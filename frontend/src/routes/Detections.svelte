<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type RuleTestCase } from '../lib/api';
  import type { AlertRecord, RuleInfo, RuleTestResult } from '../lib/types';
  import { tacticFor } from '../lib/attack';
  import { can } from '../lib/auth.svelte';
  import Badge from '../components/Badge.svelte';
  import States from '../components/States.svelte';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let rules = $state<RuleInfo[]>([]);
  let alerts = $state<AlertRecord[]>([]);
  let filter = $state('');
  let selected = $state<RuleInfo | null>(null);

  // rule editor (create + test); editing existing source needs a source GET (future)
  const SAMPLE_YAML = `title: Example rule
id: example-rule
level: medium
detection:
  selection:
    message|contains: 'suspicious'
  condition: selection
tags:
  - attack.t1059`;
  let editorOpen = $state(false);
  let draft = $state(SAMPLE_YAML);
  let testMsg = $state('a suspicious command ran');
  let testExpect = $state(true);
  let testResult = $state<RuleTestResult | null>(null);
  let actionMsg = $state<string | null>(null);

  // rule_id → number of alerts fired
  let fires = $derived.by(() => {
    const m = new Map<string, number>();
    for (const r of alerts) m.set(r.alert.rule_id, (m.get(r.alert.rule_id) ?? 0) + 1);
    return m;
  });

  async function runTest() {
    actionMsg = null;
    testResult = null;
    const cases: RuleTestCase[] = [{ name: 'case', message: testMsg, expect_match: testExpect }];
    try {
      testResult = await api.ruleTest('draft', cases, draft);
    } catch (e) {
      actionMsg = (e as Error).message;
    }
  }
  async function createRule() {
    actionMsg = null;
    try {
      const r = await api.ruleCreate(draft);
      actionMsg = `Created ${r.rule_id} — ${r.rules} rules loaded`;
      await load();
    } catch (e) {
      actionMsg = (e as Error).message;
    }
  }
  async function deleteRule(id: string) {
    if (!confirm(`Delete rule ${id}?`)) return;
    try {
      await api.ruleDelete(id);
      selected = null;
      await load();
    } catch (e) {
      actionMsg = (e as Error).message;
    }
  }

  let shown = $derived(
    rules.filter((r) => {
      const q = filter.toLowerCase();
      return (
        !q ||
        r.title.toLowerCase().includes(q) ||
        r.rule_id.toLowerCase().includes(q) ||
        (r.technique ?? '').toLowerCase().includes(q) ||
        r.tags.some((t) => t.toLowerCase().includes(q))
      );
    }),
  );

  let coverage = $derived.by(() => {
    const tactics = new Map<string, Set<string>>();
    for (const r of rules) {
      if (!r.technique) continue;
      const t = tacticFor(r.technique);
      if (!tactics.has(t)) tactics.set(t, new Set());
      tactics.get(t)!.add(r.technique);
    }
    return [...tactics.entries()].sort();
  });

  async function load() {
    loading = true;
    error = null;
    try {
      const [r, a] = await Promise.all([api.rules(), api.alerts(undefined, 1000)]);
      rules = r.rules;
      alerts = a.alerts;
      selected = rules[0] ?? null;
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
    <h1>Detections</h1>
    <div class="row">
      <input class="input flt" placeholder="filter rules…" bind:value={filter} />
      {#if can('analyst')}
        <button class="btn" onclick={() => (editorOpen = !editorOpen)}>{editorOpen ? 'Close editor' : '+ New / test rule'}</button>
      {/if}
      <button class="btn" onclick={load}>Refresh</button>
    </div>
  </div>

  {#if editorOpen && can('analyst')}
    <div class="card editor">
      <h2>Rule editor</h2>
      <div class="ed-grid">
        <div class="ed-col">
          <div class="lbl">Sigma YAML</div>
          <textarea class="input mono yaml" rows="12" bind:value={draft}></textarea>
        </div>
        <div class="ed-col">
          <div class="lbl">Test case</div>
          <input class="input" placeholder="sample message" bind:value={testMsg} />
          <label class="chk"><input type="checkbox" bind:checked={testExpect} /> expect match</label>
          <div class="row">
            <button class="btn" onclick={runTest}>Run test</button>
            <button class="btn primary" onclick={createRule}>Create rule</button>
          </div>
          {#if testResult}
            <div class="verdict" class:ok={testResult.passed} class:bad={!testResult.passed}>
              {testResult.passed ? '✓ passed' : '✗ failed'} ({testResult.cases} case{testResult.cases === 1 ? '' : 's'})
            </div>
            {#each testResult.failures as f (f)}<div class="errbox sm">{f}</div>{/each}
          {/if}
          {#if actionMsg}<div class="faint sm">{actionMsg}</div>{/if}
        </div>
      </div>
    </div>
  {/if}

  <States {loading} {error}
    empty={!loading && !error && rules.length === 0}
    emptyText="No rules loaded — set sigma.rules_dir in the config." />

  {#if !loading && !error && rules.length}
    <div class="cov card">
      <h2>Tactic coverage · {rules.length} rules</h2>
      <div class="cov-row">
        {#each coverage as [tactic, techs] (tactic)}
          <div class="cov-cell">
            <div class="tag">{tactic}</div>
            <div class="techs">{#each [...techs] as t (t)}<span class="pill">{t}</span>{/each}</div>
          </div>
        {/each}
      </div>
    </div>

    <div class="layout">
      <div class="card list">
        <h2>{shown.length} rules</h2>
        <div class="scroll" style="max-height: 64vh">
          <table>
            <thead><tr><th>severity</th><th>title</th><th>ATT&CK</th><th>fires</th></tr></thead>
            <tbody>
              {#each shown as r (r.rule_id)}
                <tr class="rule" class:active={selected?.rule_id === r.rule_id} onclick={() => (selected = r)}>
                  <td><Badge severity={r.severity} /></td>
                  <td>{r.title}</td>
                  <td>{#if r.technique}<span class="pill">{r.technique}</span>{/if}</td>
                  <td class="mono fires">{fires.get(r.rule_id) ?? 0}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>

      {#if selected}
        <div class="card detail">
          <h2>Rule</h2>
          <div class="kv"><span class="k">title</span><span>{selected.title}</span></div>
          <div class="kv"><span class="k">id</span><span class="mono">{selected.rule_id}</span></div>
          <div class="kv"><span class="k">severity</span><Badge severity={selected.severity} /></div>
          <div class="kv"><span class="k">technique</span><span>{selected.technique ?? '—'}{#if selected.technique}<span class="tag tt">{tacticFor(selected.technique)}</span>{/if}</span></div>
          <div class="kv"><span class="k">tags</span><span class="tags">{#each selected.tags as t (t)}<span class="pill">{t}</span>{/each}</span></div>
          <div class="kv"><span class="k">fires</span><span class="mono">{fires.get(selected.rule_id) ?? 0} alerts</span></div>
          {#if can('analyst')}
            <div class="row"><button class="btn danger" onclick={() => deleteRule(selected!.rule_id)}>Delete rule</button></div>
          {/if}
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  .flt { width: 240px; }
  .cov-row { display: flex; flex-wrap: wrap; gap: 18px; }
  .cov-cell { min-width: 140px; }
  .cov-cell .techs { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
  .layout { display: grid; grid-template-columns: 1fr 320px; gap: 16px; align-items: start; }
  .rule { cursor: pointer; }
  .rule.active td { background: var(--surface-2); }
  .fires { color: var(--muted); }
  .detail { display: grid; gap: 8px; align-content: start; }
  .kv { display: grid; grid-template-columns: 80px 1fr; gap: 8px; align-items: center; }
  .kv .k { color: var(--faint); font-size: 11px; text-transform: uppercase; }
  .tags { display: flex; flex-wrap: wrap; gap: 4px; }
  .tt { margin-left: 8px; }
  .editor { display: grid; gap: 10px; }
  .ed-grid { display: grid; grid-template-columns: 1fr 280px; gap: 16px; }
  .ed-col { display: grid; gap: 8px; align-content: start; }
  .lbl { font-size: 11px; text-transform: uppercase; color: var(--faint); }
  .yaml { white-space: pre; }
  .chk { font-size: 12px; color: var(--muted); display: flex; gap: 6px; align-items: center; }
  .verdict { font-weight: 600; }
  .verdict.ok { color: var(--ok); }
  .verdict.bad { color: var(--sev-high); }
  .btn.danger { color: var(--sev-high); border-color: var(--sev-high); }
  .sm { font-size: 12px; }
  @media (max-width: 1000px) { .layout { grid-template-columns: 1fr; } .ed-grid { grid-template-columns: 1fr; } }
</style>
