<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { Alert } from '../lib/types';
  import Badge from '../components/Badge.svelte';
  import States from '../components/States.svelte';
  import { fmtTime } from '../lib/format';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let alerts = $state<Alert[]>([]);
  let technique = $state('');

  async function load() {
    loading = true;
    error = null;
    try {
      alerts = (await api.alerts(technique || undefined, 500)).alerts;
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
    <h1>Alerts</h1>
    <div class="row">
      <input class="input flt" placeholder="filter by technique (e.g. T1110.001)" bind:value={technique}
        onkeydown={(e) => e.key === 'Enter' && load()} />
      <button class="btn" onclick={load}>Apply</button>
      {#if technique}<button class="btn" onclick={() => { technique = ''; load(); }}>Clear</button>{/if}
    </div>
  </div>

  <States {loading} {error} empty={!loading && !error && alerts.length === 0} emptyText="No alerts — run a node over seeds/ to generate some." />

  {#if !loading && !error && alerts.length}
    <div class="card">
      <h2>{alerts.length} alerts</h2>
      <div class="scroll" style="max-height: 75vh">
        <table>
          <thead><tr><th>time</th><th>severity</th><th>rule</th><th>title</th><th>ATT&CK</th><th>events</th></tr></thead>
          <tbody>
            {#each alerts as a (a.rule_id + a.events.join() + a.ts)}
              <tr>
                <td class="mono nowrap">{fmtTime(a.ts)}</td>
                <td><Badge severity={a.severity} /></td>
                <td class="mono">{a.rule_id}</td>
                <td>{a.title}</td>
                <td>
                  {#if a.technique}
                    <button class="pill linklike" onclick={() => { technique = a.technique!; load(); }}>{a.technique}</button>
                  {/if}
                </td>
                <td class="mono faint">{a.events.length}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <div class="muted note">Status workflow (open / ack / closed), assignment &amp; bulk actions are planned (needs <code>PATCH /alerts/&#123;id&#125;</code> — FRONTEND.md §8).</div>
    </div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  .flt { width: 280px; }
  .nowrap { white-space: nowrap; }
  .linklike { cursor: pointer; }
  .note { font-size: 12px; margin-top: 12px; }
</style>
