<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { ValidationReport, SystemInfo } from '../lib/types';
  import States from '../components/States.svelte';
  import { can } from '../lib/auth.svelte';

  const isAdmin = can('admin');

  let loading = $state(true);
  let error = $state<string | null>(null);
  let path = $state('');
  let yaml = $state('');
  let original = $state('');
  let report = $state<ValidationReport | null>(null);
  let system = $state<SystemInfo | null>(null);

  let validating = $state(false);
  let saving = $state(false);
  let saveMsg = $state<string | null>(null);
  let saveOk = $state(false);
  let restartRequired = $state(false);

  let dirty = $derived(yaml !== original);
  let hasErrors = $derived(!!report && !report.ok);

  let debounce: ReturnType<typeof setTimeout> | null = null;

  async function load() {
    loading = true;
    error = null;
    saveMsg = null;
    try {
      const [cfg, sys] = await Promise.all([api.getConfig(), api.system().catch(() => null)]);
      path = cfg.path;
      yaml = cfg.yaml;
      original = cfg.yaml;
      report = cfg.report;
      system = sys;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  async function validate() {
    validating = true;
    try {
      report = (await api.validateConfig(yaml)).report;
    } catch (e) {
      report = { ok: false, errors: [(e as Error).message], warnings: [] };
    } finally {
      validating = false;
    }
  }

  function onEdit() {
    saveMsg = null;
    if (debounce) clearTimeout(debounce);
    debounce = setTimeout(validate, 500);
  }

  async function save() {
    if (!isAdmin) return;
    saving = true;
    saveMsg = null;
    try {
      const res = await api.saveConfig(yaml);
      report = res.report;
      saveOk = res.ok;
      restartRequired = !!res.restart_required;
      if (res.ok) {
        original = yaml;
        saveMsg =
          res.message ??
          `Saved.${res.rules_reloaded != null ? ` ${res.rules_reloaded} rules reloaded.` : ''}`;
      } else {
        saveMsg = 'Not saved — fix the errors below.';
      }
    } catch (e) {
      saveOk = false;
      saveMsg = `error: ${(e as Error).message}`;
    } finally {
      saving = false;
    }
  }

  onMount(load);
</script>

<div class="page">
  <div class="head">
    <div>
      <h1>Configuration</h1>
      <div class="sub">Declarative platform config · the source of truth (DESIGN §13)</div>
    </div>
    <div class="hactions">
      <button class="btn" onclick={load} disabled={loading}>Reload from disk</button>
      <button class="btn" onclick={validate} disabled={loading || validating}>Validate</button>
      {#if isAdmin}
        <button class="btn primary" onclick={save} disabled={loading || saving || hasErrors || !dirty}>
          {saving ? 'Saving…' : 'Save'}
        </button>
      {/if}
    </div>
  </div>

  {#if !isAdmin}
    <div class="card"><div class="errbox">Platform configuration requires the <b>admin</b> role.</div></div>
  {:else}
    <div class="card warn-banner">
      ⚠ This edits the raw config file <code>{path || '…'}</code>, which includes secrets (JWT signing key,
      credentials, enrollment tokens). Changes are validated before writing and the previous file is backed up.
      Most changes apply on <b>restart</b>; Sigma rules hot-reload.
    </div>

    <States {loading} {error} />

    {#if !loading && !error}
      {#if saveMsg}
        <div class="card banner" class:ok={saveOk} class:bad={!saveOk}>
          {saveMsg}
          {#if saveOk && restartRequired}<span class="restart">restart the node to fully apply</span>{/if}
        </div>
      {/if}

      <div class="layout">
        <div class="card editor-card">
          <div class="ehead">
            <h2>{path}</h2>
            <span class="spacer"></span>
            {#if dirty}<span class="pill dirty">unsaved changes</span>{/if}
            {#if report}
              {#if report.ok}
                <span class="verdict ok">✓ valid{report.warnings.length ? ` · ${report.warnings.length} warning(s)` : ''}</span>
              {:else}
                <span class="verdict bad">✗ {report.errors.length} error(s)</span>
              {/if}
            {/if}
          </div>
          <textarea
            class="input mono editor"
            bind:value={yaml}
            oninput={onEdit}
            spellcheck="false"
            wrap="off"
          ></textarea>

          {#if report && (report.errors.length || report.warnings.length)}
            <div class="reports">
              {#each report.errors as e (e)}<div class="line err">✗ {e}</div>{/each}
              {#each report.warnings as w (w)}<div class="line warn">⚠ {w}</div>{/each}
            </div>
          {/if}
        </div>

        <div class="side">
          <div class="card">
            <h2>Running state</h2>
            {#if system}
              <div class="kv">
                <span>roles</span><span>{system.roles.join(', ') || '—'}</span>
                <span>transport</span><span>{system.transport}</span>
                <span>inputs</span><span>{system.sources.length}</span>
                <span>pipelines</span><span>{system.pipelines.length}</span>
                <span>rules</span><span>{system.rule_count}</span>
                <span>retention</span><span>{system.retention_hot} / {system.retention_warm} / {system.retention_cold}</span>
                <span>auth</span><span>{system.auth_enabled ? 'enabled' : 'disabled'}</span>
                <span>persistence</span><span>{system.persistence ? 'on' : 'off'}</span>
              </div>
              <div class="note faint">Running state reflects the last <b>started</b> config. The editor shows the
                desired file — save, then restart to reconcile.</div>
            {:else}
              <div class="faint">system info unavailable</div>
            {/if}
          </div>

          <div class="card">
            <h2>Sections</h2>
            <ul class="sections">
              <li><b>inputs</b> — sources (file, syslog, …)</li>
              <li><b>pipelines</b> — normalize · enrich · route</li>
              <li><b>index</b> — hot/warm/cold retention + paths</li>
              <li><b>sigma</b> — detection rules + alert outputs</li>
              <li><b>detectors</b> — custom detectors (dga, ioc)</li>
              <li><b>auth</b> — users + RBAC (secrets)</li>
              <li><b>edr</b> — agent gateway + tokens</li>
              <li><b>cluster</b> — roles, transport, sharding</li>
            </ul>
          </div>
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
  .head h1 { margin: 0; }
  .sub { color: var(--muted); font-size: 13px; margin-top: 2px; }
  .hactions { display: flex; gap: 8px; }
  .btn.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .warn-banner { border-color: var(--sev-medium); color: var(--muted); font-size: 13px; }
  .warn-banner code { color: var(--text); }
  .banner { font-size: 13px; }
  .banner.ok { border-color: var(--ok); color: var(--ok); }
  .banner.bad { border-color: var(--sev-high); color: var(--sev-high); }
  .restart { margin-left: 8px; color: var(--sev-medium); }
  .layout { display: grid; grid-template-columns: 1fr 300px; gap: 16px; align-items: start; }
  .editor-card { display: grid; gap: 10px; }
  .ehead { display: flex; align-items: center; gap: 10px; }
  .ehead h2 { margin: 0; font-family: var(--mono); font-size: 13px; color: var(--muted); }
  .spacer { flex: 1; }
  .verdict.ok { color: var(--ok); font-size: 12px; }
  .verdict.bad { color: var(--sev-high); font-size: 12px; }
  .dirty { color: var(--sev-medium); border-color: var(--sev-medium); }
  .editor { width: 100%; min-height: 60vh; resize: vertical; line-height: 1.5; font-size: 12.5px; white-space: pre; }
  .reports { display: grid; gap: 4px; }
  .line { font-size: 12px; padding: 4px 8px; border-radius: 4px; font-family: var(--mono); }
  .line.err { color: var(--sev-high); background: color-mix(in srgb, var(--sev-high) 8%, transparent); }
  .line.warn { color: var(--sev-medium); background: color-mix(in srgb, var(--sev-medium) 8%, transparent); }
  .side { display: grid; gap: 16px; }
  .kv { display: grid; grid-template-columns: 90px 1fr; gap: 4px 12px; font-size: 13px; }
  .kv span:nth-child(odd) { color: var(--faint); }
  .note { font-size: 11px; margin-top: 10px; }
  .sections { margin: 0; padding-left: 16px; display: grid; gap: 4px; font-size: 12px; color: var(--muted); }
  .sections b { color: var(--text); }
  @media (max-width: 1000px) { .layout { grid-template-columns: 1fr; } }
</style>
