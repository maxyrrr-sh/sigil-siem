<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api } from '../lib/api';
  import type { Agent, EdrCommand, EdrActionBody } from '../lib/types';
  import States from '../components/States.svelte';
  import { fmtTime } from '../lib/format';

  let loading = $state(true);
  let error = $state<string | null>(null);
  let agents = $state<Agent[]>([]);
  let selectedId = $state<string | null>(null);
  let commands = $state<EdrCommand[]>([]);
  let actionMsg = $state<string | null>(null);
  let stream: EventSource | null = null;

  // Pending action awaiting confirmation.
  type Pending = { type: string; label: string; input?: 'pid' | 'path'; value: string };
  let pending = $state<Pending | null>(null);

  let selected = $derived(agents.find((a) => a.agent_id === selectedId) ?? null);

  async function loadAgents() {
    loading = true;
    error = null;
    try {
      agents = (await api.edrAgents()).agents;
      if (!selectedId && agents[0]) selectedId = agents[0].agent_id;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  async function loadDetail(id: string) {
    try {
      commands = (await api.edrAgent(id)).commands;
    } catch (e) {
      commands = [];
    }
  }

  function pick(id: string) {
    selectedId = id;
    loadDetail(id);
  }

  function ask(type: string, label: string, input?: 'pid' | 'path') {
    pending = { type, label, input, value: '' };
    actionMsg = null;
  }

  async function confirmAction() {
    if (!pending || !selected) return;
    const body: EdrActionBody = { type: pending.type };
    if (pending.input === 'pid') body.pid = Number(pending.value);
    if (pending.input === 'path') body.path = pending.value;
    try {
      const rec = await api.edrAction(selected.agent_id, body);
      actionMsg = `queued ${rec.command_type} (${rec.status})`;
      pending = null;
      await loadDetail(selected.agent_id);
    } catch (e) {
      actionMsg = `error: ${(e as Error).message}`;
    }
  }

  function statusChip(a: Agent): { text: string; cls: string } {
    if (a.isolated) return { text: 'isolated', cls: 'iso' };
    if (a.connected) return { text: 'online', cls: 'ok' };
    return { text: 'offline', cls: 'off' };
  }

  onMount(() => {
    loadAgents().then(() => {
      if (selectedId) loadDetail(selectedId);
    });
    // Live fleet status via SSE.
    stream = api.streamAgents();
    stream.onmessage = (e) => {
      try {
        const next = JSON.parse(e.data) as Agent[];
        if (Array.isArray(next) && next.length) agents = next;
      } catch {
        /* ignore keep-alives */
      }
    };
  });
  onDestroy(() => stream?.close());
</script>

<div class="page">
  <div class="head">
    <h1>Agents</h1>
    <button class="btn" onclick={loadAgents}>Refresh</button>
  </div>

  <div class="card info">
    <p class="muted">
      Enrolled <b>sigil-agent</b> endpoints (DESIGN §12). Agents stream process / file /
      network / persistence telemetry and execute response actions. Isolation always keeps
      the Sigil control channel reachable.
    </p>
  </div>

  <States {loading} {error}
    empty={!loading && !error && agents.length === 0}
    emptyText="No agents enrolled. Issue an enrollment token (Admin) and run `sigil-agent enroll`." />

  {#if !loading && !error && agents.length}
    <div class="layout">
      <div class="card list">
        <h2>{agents.length} agents</h2>
        {#each agents as a (a.agent_id)}
          <button class="agent" class:active={selectedId === a.agent_id} onclick={() => pick(a.agent_id)}>
            <div class="row">
              <b>{a.hostname || a.agent_id.slice(0, 8)}</b>
              <span class="spacer"></span>
              <span class="chip {statusChip(a).cls}">{statusChip(a).text}</span>
            </div>
            <div class="meta">{a.os} {a.os_version} · v{a.agent_version}</div>
            <div class="meta faint">seen {a.last_seen ? fmtTime(a.last_seen) : '—'}</div>
          </button>
        {/each}
      </div>

      {#if selected}
        <div class="detail">
          <div class="card">
            <div class="row">
              <h2 style="margin:0">{selected.hostname}</h2>
              <span class="spacer"></span>
              <span class="chip {statusChip(selected).cls}">{statusChip(selected).text}</span>
            </div>
            <div class="kv">
              <span>agent id</span><code>{selected.agent_id}</code>
              <span>os</span><span>{selected.os} {selected.os_version}</span>
              <span>version</span><span>{selected.agent_version}</span>
              <span>enrolled</span><span>{fmtTime(selected.enrolled_ts)}</span>
            </div>
          </div>

          <div class="card">
            <h2>Response actions</h2>
            <div class="actions">
              {#if selected.isolated}
                <button class="btn" onclick={() => ask('unisolate_host', 'Remove network isolation')}>Un-isolate</button>
              {:else}
                <button class="btn danger" onclick={() => ask('isolate_host', 'Network-isolate this host')}>Isolate host</button>
              {/if}
              <button class="btn danger" onclick={() => ask('kill_process', 'Kill a process', 'pid')}>Kill process…</button>
              <button class="btn" onclick={() => ask('quarantine_file', 'Quarantine a file', 'path')}>Quarantine file…</button>
              <button class="btn" onclick={() => ask('fetch_file', 'Fetch a file', 'path')}>Fetch file…</button>
            </div>
            {#if actionMsg}<div class="amsg">{actionMsg}</div>{/if}
          </div>

          <div class="card">
            <h2>Command history</h2>
            {#if commands.length === 0}
              <div class="faint">No commands issued.</div>
            {:else}
              <table class="cmds">
                <thead><tr><th>time</th><th>action</th><th>status</th><th>by</th><th>result</th></tr></thead>
                <tbody>
                  {#each commands as c (c.command_id)}
                    <tr>
                      <td class="mono">{fmtTime(c.issued_ts)}</td>
                      <td>{c.command_type}</td>
                      <td><span class="chip st-{c.status}">{c.status}</span></td>
                      <td>{c.issued_by}</td>
                      <td class="faint">{c.result_message ?? '—'}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}
          </div>
        </div>
      {/if}
    </div>
  {/if}
</div>

{#if pending}
  <div
    class="modal-bg"
    onclick={() => (pending = null)}
    onkeydown={(e) => e.key === 'Escape' && (pending = null)}
    role="presentation"
  >
    <div
      class="modal"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
      role="dialog"
      aria-modal="true"
      tabindex="-1"
    >
      <h3>{pending.label}</h3>
      <p class="muted">Target: <b>{selected?.hostname}</b></p>
      {#if pending.input === 'pid'}
        <input class="input" type="number" placeholder="pid" bind:value={pending.value} />
      {:else if pending.input === 'path'}
        <input class="input" type="text" placeholder="/path/to/file" bind:value={pending.value} />
      {/if}
      <div class="modal-actions">
        <button class="btn" onclick={() => (pending = null)}>Cancel</button>
        <button class="btn danger" onclick={confirmAction}
          disabled={!!pending.input && !pending.value}>Confirm</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; justify-content: space-between; }
  .info p { margin: 0; max-width: 900px; }
  .layout { display: grid; grid-template-columns: 300px 1fr; gap: 16px; align-items: start; }
  .list { display: grid; gap: 8px; align-content: start; }
  .agent { text-align: left; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px; cursor: pointer; color: var(--text); display: grid; gap: 4px; }
  .agent:hover { border-color: var(--border-2); }
  .agent.active { border-color: var(--accent); box-shadow: inset 2px 0 0 var(--accent); }
  .row { display: flex; align-items: center; gap: 8px; }
  .spacer { flex: 1; }
  .meta { font-size: 12px; color: var(--muted); }
  .detail { display: grid; gap: 16px; }
  .kv { display: grid; grid-template-columns: 90px 1fr; gap: 4px 12px; margin-top: 8px; font-size: 13px; }
  .kv span:nth-child(odd) { color: var(--faint); }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; }
  .amsg { margin-top: 10px; font-size: 13px; color: var(--muted); }
  .chip { font-size: 11px; padding: 1px 7px; border-radius: 10px; border: 1px solid var(--border); }
  .chip.ok { color: var(--ok); border-color: var(--ok); }
  .chip.off { color: var(--faint); }
  .chip.iso { color: var(--sev-high); border-color: var(--sev-high); }
  .st-completed { color: var(--ok); border-color: var(--ok); }
  .st-failed { color: var(--sev-high); border-color: var(--sev-high); }
  .st-pending, .st-sent { color: var(--sev-medium); }
  .cmds { width: 100%; border-collapse: collapse; font-size: 13px; }
  .cmds th { text-align: left; color: var(--faint); font-weight: 500; padding: 4px 8px; border-bottom: 1px solid var(--border); }
  .cmds td { padding: 4px 8px; border-bottom: 1px solid var(--border); }
  .btn.danger { color: var(--sev-high); border-color: var(--sev-high); }
  .modal-bg { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: grid; place-items: center; z-index: 50; }
  .modal { background: var(--surface); border: 1px solid var(--border-2); border-radius: 8px; padding: 20px; width: min(420px, 90vw); display: grid; gap: 12px; }
  .modal h3 { margin: 0; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 8px; }
  @media (max-width: 1000px) { .layout { grid-template-columns: 1fr; } }
</style>
