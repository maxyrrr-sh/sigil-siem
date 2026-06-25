<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { EvalReport } from '../lib/types';
  import BarChart from '../components/BarChart.svelte';
  import States from '../components/States.svelte';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let seed = $state(1);
  let report = $state<EvalReport | null>(null);

  let ariBars = $derived(report ? report.rows.map((r) => ({ label: r.variant, value: r.ari })) : []);
  let chainBars = $derived(report ? report.rows.map((r) => ({ label: r.variant, value: r.chain_similarity })) : []);

  async function run() {
    loading = true;
    error = null;
    try {
      report = await api.evaluate(seed);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }
  onMount(run);
</script>

<div class="page">
  <div class="head">
    <h1>Evaluation</h1>
    <div class="row">
      <label class="seedlbl">seed <input class="input seed" type="number" bind:value={seed} min="0" /></label>
      <button class="btn primary" onclick={run} disabled={loading}>Run</button>
    </div>
  </div>

  <States {loading} {error} />

  {#if !loading && !error && report}
    <div class="card">
      <h2>Comparison · {report.scenario} ({report.alerts} alerts)</h2>
      <div class="scroll">
        <table>
          <thead><tr><th>variant</th><th>ARI</th><th>NMI</th><th>reduction</th><th>tech-F1</th><th>chain-sim</th><th>incidents</th></tr></thead>
          <tbody>
            {#each report.rows as r (r.variant)}
              <tr class:hl={r.variant === 'combined'}>
                <td>{r.variant}</td>
                <td class="mono">{r.ari.toFixed(2)}</td>
                <td class="mono">{r.nmi.toFixed(2)}</td>
                <td class="mono">{r.alert_reduction.toFixed(2)}</td>
                <td class="mono">{r.technique_f1.toFixed(2)}</td>
                <td class="mono">{r.chain_similarity.toFixed(2)}</td>
                <td class="mono">{r.incidents}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>

    <div class="charts">
      <div class="card"><h2>ARI (campaign grouping)</h2><BarChart data={ariBars} max={1} fmt={(v) => v.toFixed(2)} /></div>
      <div class="card"><h2>Chain similarity (reconstruction)</h2><BarChart data={chainBars} max={1} fmt={(v) => v.toFixed(2)} color="var(--tactic)" /></div>
    </div>
    <div class="muted note">The combined approach should dominate the sigma-only baseline on grouping (ARI/NMI), alert-reduction, and chain reconstruction — the research claim (DESIGN §11). On this clean synthetic scenario the ablations may tie with combined.</div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .seedlbl { color: var(--muted); font-size: 13px; }
  .seed { width: 80px; display: inline-block; margin-left: 6px; }
  tr.hl td { background: var(--surface-2); color: var(--text-strong); }
  .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .note { font-size: 12px; max-width: 900px; }
  @media (max-width: 900px) { .charts { grid-template-columns: 1fr; } }
</style>
