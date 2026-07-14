<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api } from '../lib/api';
  import type { Agent, EdrCommand, EdrActionBody, EdrToken, SigilEvent } from '../lib/types';
  import States from '../components/States.svelte';
  import { fmtTime, className } from '../lib/format';
  import { can } from '../lib/auth.svelte';

  type Tab = 'fleet' | 'response' | 'enrollment';
  let tab = $state<Tab>('fleet');

  let loading = $state(true);
  let error = $state<string | null>(null);
  let agents = $state<Agent[]>([]);
  let allCommands = $state<EdrCommand[]>([]);
  let tokens = $state<EdrToken[]>([]);
  let stream: EventSource | null = null;

  // Selected-agent detail.
  let selectedId = $state<string | null>(null);
  let telemetry = $state<SigilEvent[]>([]);
  let agentCommands = $state<EdrCommand[]>([]);
  let actionMsg = $state<string | null>(null);

  // Pending action + issued token.
  type Pending = { type: string; label: string; input?: 'pid' | 'path'; danger: boolean; value: string };
  let pending = $state<Pending | null>(null);
  let issuedToken = $state<string | null>(null);
  let tokenLabel = $state('');
  let copied = $state(false);

  let selected = $derived(agents.find((a) => a.agent_id === selectedId) ?? null);
  let hostFor = $derived(new Map(agents.map((a) => [a.agent_id, a.hostname])));

  const isAnalyst = can('analyst');
  const isAdmin = can('admin');

  // Fleet stats.
  let stats = $derived({
    total: agents.length,
    online: agents.filter((a) => a.connected).length,
    isolated: agents.filter((a) => a.isolated).length,
    pending: allCommands.filter((c) => c.status === 'pending' || c.status === 'sent').length,
  });

  async function loadAll() {
    loading = true;
    error = null;
    try {
      agents = (await api.edrAgents()).agents;
      allCommands = (await api.edrCommands()).commands;
      if (isAdmin) {
        try {
          tokens = (await api.edrTokens()).tokens;
        } catch {
          tokens = [];
        }
      }
      if (!selectedId && agents[0]) selectedId = agents[0].agent_id;
      if (selectedId) await loadDetail(selectedId);
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  async function loadDetail(id: string) {
    try {
      agentCommands = (await api.edrAgent(id)).commands;
    } catch {
      agentCommands = [];
    }
    try {
      telemetry = (await api.search(id, 40)).events;
    } catch {
      telemetry = [];
    }
  }

  function pick(id: string) {
    selectedId = id;
    actionMsg = null;
    loadDetail(id);
  }

  function ask(type: string, label: string, opts: { input?: 'pid' | 'path'; danger?: boolean } = {}) {
    pending = { type, label, input: opts.input, danger: !!opts.danger, value: '' };
    actionMsg = null;
  }

  async function confirmAction() {
    if (!pending || !selected) return;
    const body: EdrActionBody = { type: pending.type };
    if (pending.input === 'pid') body.pid = Number(pending.value);
    if (pending.input === 'path') body.path = pending.value;
    try {
      const rec = await api.edrAction(selected.agent_id, body);
      actionMsg = `queued ${rec.command_type} · ${rec.status}`;
      pending = null;
      await loadDetail(selected.agent_id);
      allCommands = (await api.edrCommands()).commands;
    } catch (e) {
      actionMsg = `error: ${(e as Error).message}`;
    }
  }

  async function issueToken() {
    try {
      const r = await api.edrIssueToken(tokenLabel || undefined);
      issuedToken = r.token;
      tokenLabel = '';
      copied = false;
      tokens = (await api.edrTokens()).tokens;
    } catch (e) {
      actionMsg = `error: ${(e as Error).message}`;
    }
  }

  async function copyToken() {
    if (!issuedToken) return;
    try {
      await navigator.clipboard.writeText(issuedToken);
      copied = true;
    } catch {
      copied = false;
    }
  }

  function statusChip(a: Agent): { text: string; cls: string } {
    if (a.isolated) return { text: 'isolated', cls: 'iso' };
    if (a.connected) return { text: 'online', cls: 'ok' };
    return { text: 'offline', cls: 'off' };
  }

  onMount(() => {
    loadAll();
    stream = api.streamAgents();
    stream.onmessage = (e) => {
      try {
        const next = JSON.parse(e.data) as Agent[];
        if (Array.isArray(next)) agents = next;
      } catch {
        /* keep-alive */
      }
    };
  });
  onDestroy(() => stream?.close());
</script>

<div class="page">
  <div class="head">
    <div>
      <h1>EDR</h1>
      <div class="sub">Endpoint detection &amp; response · agent fleet</div>
    </div>
    <button class="btn" onclick={loadAll}>Refresh</button>
  </div>

  <div class="kpis">
    <div class="card kpi"><div class="n">{stats.total}</div><div class="muted">agents</div></div>
    <div class="card kpi ok"><div class="n">{stats.online}</div><div class="muted">online</div></div>
    <div class="card kpi warn"><div class="n">{stats.isolated}</div><div class="muted">isolated</div></div>
    <div class="card kpi"><div class="n">{stats.pending}</div><div class="muted">commands pending</div></div>
  </div>

  <div class="tabs">
    <button class="tab" class:active={tab === 'fleet'} onclick={() => (tab = 'fleet')}>Fleet</button>
    <button class="tab" class:active={tab === 'response'} onclick={() => (tab = 'response')}>Response ({allCommands.length})</button>
    {#if isAdmin}
      <button class="tab" class:active={tab === 'enrollment'} onclick={() => (tab = 'enrollment')}>Enrollment</button>
    {/if}
  </div>

  <States {loading} {error}
    empty={!loading && !error && agents.length === 0 && tab === 'fleet'}
    emptyText="No agents enrolled. Issue an enrollment token (Enrollment tab) and run `sigil-agent enroll`." />

  <!-- FLEET -->
  {#if tab === 'fleet' && !loading && !error && agents.length}
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
          {#if selected.isolated}
            <div class="banner">⚠ This host is network-isolated. Only the Sigil control channel is reachable.</div>
          {/if}

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
              <span>last seen</span><span>{selected.last_seen ? fmtTime(selected.last_seen) : '—'}</span>
            </div>
          </div>

          <div class="card">
            <div class="row"><h2 style="margin:0">Response actions</h2>
              {#if !isAnalyst}<span class="spacer"></span><span class="faint sm">requires analyst role</span>{/if}
            </div>
            <div class="actions">
              {#if selected.isolated}
                <button class="btn" disabled={!isAnalyst} onclick={() => ask('unisolate_host', 'Remove network isolation')}>Un-isolate</button>
              {:else}
                <button class="btn danger" disabled={!isAnalyst} onclick={() => ask('isolate_host', 'Network-isolate this host', { danger: true })}>Isolate host</button>
              {/if}
              <button class="btn danger" disabled={!isAnalyst} onclick={() => ask('kill_process', 'Kill a process', { input: 'pid', danger: true })}>Kill process…</button>
              <button class="btn" disabled={!isAnalyst} onclick={() => ask('quarantine_file', 'Quarantine a file', { input: 'path', danger: true })}>Quarantine file…</button>
              <button class="btn" disabled={!isAnalyst} onclick={() => ask('fetch_file', 'Fetch a file', { input: 'path' })}>Fetch file…</button>
            </div>
            {#if actionMsg}<div class="amsg">{actionMsg}</div>{/if}
          </div>

          <div class="cols">
            <div class="card">
              <h2>Recent telemetry</h2>
              {#if telemetry.length === 0}
                <div class="faint">No indexed telemetry for this agent yet.</div>
              {:else}
                <div class="scroll" style="max-height: 320px">
                  <table class="tel">
                    <thead><tr><th>time</th><th>class</th><th>event</th></tr></thead>
                    <tbody>
                      {#each telemetry as e (e.id)}
                        <tr>
                          <td class="mono nowrap">{fmtTime(e.ts)}</td>
                          <td><span class="pill cls">{className(e.ocsf_class)}</span></td>
                          <td class="msg">{e.message}</td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}
            </div>

            <div class="card">
              <h2>Command history</h2>
              {#if agentCommands.length === 0}
                <div class="faint">No commands issued.</div>
              {:else}
                <div class="scroll" style="max-height: 320px">
                  <table class="cmds">
                    <thead><tr><th>time</th><th>action</th><th>status</th><th>by</th></tr></thead>
                    <tbody>
                      {#each agentCommands as c (c.command_id)}
                        <tr title={c.result_message ?? ''}>
                          <td class="mono nowrap">{fmtTime(c.issued_ts)}</td>
                          <td>{c.command_type}</td>
                          <td><span class="chip st-{c.status}">{c.status}</span></td>
                          <td>{c.issued_by}</td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}
            </div>
          </div>
        </div>
      {/if}
    </div>
  {/if}

  <!-- RESPONSE -->
  {#if tab === 'response' && !loading && !error}
    <div class="card">
      <h2>Command audit trail</h2>
      {#if allCommands.length === 0}
        <div class="faint">No response commands issued yet.</div>
      {:else}
        <div class="scroll" style="max-height: 560px">
          <table class="cmds wide">
            <thead><tr><th>time</th><th>agent</th><th>action</th><th>status</th><th>by</th><th>result</th></tr></thead>
            <tbody>
              {#each allCommands as c (c.command_id)}
                <tr>
                  <td class="mono nowrap">{fmtTime(c.issued_ts)}</td>
                  <td>{hostFor.get(c.agent_id) ?? c.agent_id.slice(0, 8)}</td>
                  <td>{c.command_type}</td>
                  <td><span class="chip st-{c.status}">{c.status}</span></td>
                  <td>{c.issued_by}</td>
                  <td class="faint msg">{c.result_message ?? '—'}{#if c.result_bytes} · {c.result_bytes}B{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  {/if}

  <!-- ENROLLMENT -->
  {#if tab === 'enrollment' && isAdmin && !loading && !error}
    <div class="cols">
      <div class="card">
        <h2>Issue enrollment token</h2>
        <p class="muted sm">Agents present a pre-shared token once, at <code>sigil-agent enroll</code>. The raw value is shown only here — copy it now.</p>
        <div class="issue">
          <input class="input" placeholder="label (optional)" bind:value={tokenLabel} />
          <button class="btn" onclick={issueToken}>Issue token</button>
        </div>
        {#if issuedToken}
          <div class="tokenbox">
            <code class="tok">{issuedToken}</code>
            <button class="btn sm" onclick={copyToken}>{copied ? 'copied ✓' : 'copy'}</button>
          </div>
        {/if}
      </div>

      <div class="card">
        <h2>Issued tokens</h2>
        {#if tokens.length === 0}
          <div class="faint">No enrollment tokens.</div>
        {:else}
          <table class="cmds">
            <thead><tr><th>prefix</th><th>label</th><th>created</th><th>by</th></tr></thead>
            <tbody>
              {#each tokens as t (t.prefix + t.created_ts)}
                <tr>
                  <td class="mono">{t.prefix}…</td>
                  <td>{t.label}</td>
                  <td class="nowrap">{fmtTime(t.created_ts)}</td>
                  <td>{t.created_by ?? '—'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </div>
    </div>
  {/if}
</div>

{#if pending}
  <div class="modal-bg" onclick={() => (pending = null)} onkeydown={(e) => e.key === 'Escape' && (pending = null)} role="presentation">
    <div class="modal" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()} role="dialog" aria-modal="true" tabindex="-1">
      <h3>{pending.label}</h3>
      <p class="muted">Target: <b>{selected?.hostname}</b></p>
      {#if pending.input === 'pid'}
        <input class="input" type="number" placeholder="pid" bind:value={pending.value} />
      {:else if pending.input === 'path'}
        <input class="input" type="text" placeholder="/path/to/file" bind:value={pending.value} />
      {/if}
      {#if pending.danger}<div class="warn-note">This is a containment action and is recorded in the audit trail.</div>{/if}
      <div class="modal-actions">
        <button class="btn" onclick={() => (pending = null)}>Cancel</button>
        <button class="btn" class:danger={pending.danger} onclick={confirmAction} disabled={!!pending.input && !pending.value}>Confirm</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: flex-start; justify-content: space-between; }
  .head h1 { margin: 0; }
  .sub { color: var(--muted); font-size: 13px; margin-top: 2px; }
  .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
  .kpi .n { font-size: 26px; font-weight: 600; color: var(--text-strong); }
  .kpi.ok .n { color: var(--ok); }
  .kpi.warn .n { color: var(--sev-high); }
  .tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); }
  .tab { background: transparent; border: 0; border-bottom: 2px solid transparent; color: var(--muted); padding: 8px 14px; cursor: pointer; font: inherit; }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--text-strong); border-bottom-color: var(--accent); }
  .layout { display: grid; grid-template-columns: 300px 1fr; gap: 16px; align-items: start; }
  .list { display: grid; gap: 8px; align-content: start; }
  .agent { text-align: left; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px; cursor: pointer; color: var(--text); display: grid; gap: 4px; }
  .agent:hover { border-color: var(--border-2); }
  .agent.active { border-color: var(--accent); box-shadow: inset 2px 0 0 var(--accent); }
  .row { display: flex; align-items: center; gap: 8px; }
  .spacer { flex: 1; }
  .meta { font-size: 12px; color: var(--muted); }
  .detail { display: grid; gap: 16px; }
  .banner { background: color-mix(in srgb, var(--sev-high) 12%, transparent); border: 1px solid var(--sev-high); color: var(--sev-high); border-radius: 6px; padding: 8px 12px; font-size: 13px; }
  .kv { display: grid; grid-template-columns: 90px 1fr; gap: 4px 12px; margin-top: 8px; font-size: 13px; }
  .kv span:nth-child(odd) { color: var(--faint); }
  .kv code { word-break: break-all; }
  .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 6px; }
  .amsg { margin-top: 10px; font-size: 13px; color: var(--muted); }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .chip { font-size: 11px; padding: 1px 7px; border-radius: 10px; border: 1px solid var(--border); white-space: nowrap; }
  .chip.ok { color: var(--ok); border-color: var(--ok); }
  .chip.off { color: var(--faint); }
  .chip.iso { color: var(--sev-high); border-color: var(--sev-high); }
  .st-completed { color: var(--ok); border-color: var(--ok); }
  .st-failed { color: var(--sev-high); border-color: var(--sev-high); }
  .st-pending, .st-sent { color: var(--sev-medium); border-color: var(--sev-medium); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--faint); font-weight: 500; padding: 4px 8px; border-bottom: 1px solid var(--border); position: sticky; top: 0; background: var(--surface); }
  td { padding: 4px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  .nowrap { white-space: nowrap; }
  .msg { max-width: 420px; overflow: hidden; text-overflow: ellipsis; }
  .cls { font-size: 10px; }
  .scroll { overflow: auto; }
  .btn.danger { color: var(--sev-high); border-color: var(--sev-high); }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn.sm { padding: 2px 8px; font-size: 12px; }
  .sm { font-size: 12px; }
  .issue { display: flex; gap: 8px; margin-top: 8px; }
  .issue .input { flex: 1; }
  .tokenbox { margin-top: 12px; display: flex; gap: 8px; align-items: center; background: var(--bg); border: 1px solid var(--border-2); border-radius: 6px; padding: 8px 10px; }
  .tok { font-family: var(--mono); word-break: break-all; flex: 1; font-size: 12px; }
  .modal-bg { position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: grid; place-items: center; z-index: 50; }
  .modal { background: var(--surface); border: 1px solid var(--border-2); border-radius: 8px; padding: 20px; width: min(440px, 90vw); display: grid; gap: 12px; }
  .modal h3 { margin: 0; }
  .warn-note { font-size: 12px; color: var(--sev-medium); }
  .modal-actions { display: flex; justify-content: flex-end; gap: 8px; }
  @media (max-width: 1000px) { .layout { grid-template-columns: 1fr; } .cols { grid-template-columns: 1fr; } .kpis { grid-template-columns: repeat(2, 1fr); } }
</style>
