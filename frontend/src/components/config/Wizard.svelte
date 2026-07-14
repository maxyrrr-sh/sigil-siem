<script lang="ts">
  import { api } from '../../lib/api';
  import type { PlatformConfig, ConfigMeta } from '../../lib/types';
  import Toggle from './Toggle.svelte';
  import Field from './Field.svelte';

  let {
    base,
    meta,
    ondone,
    oncancel,
  }: {
    base: PlatformConfig;
    meta: ConfigMeta;
    ondone: () => void;
    oncancel: () => void;
  } = $props();

  // Working copy the wizard mutates, then saves in one shot (a one-time clone of
  // the current config — the wizard intentionally does not track later changes).
  // svelte-ignore state_referenced_locally
  let wc = $state<PlatformConfig>(structuredClone($state.snapshot(base)));

  const STEPS = ['Welcome', 'Deployment', 'Data input', 'Detections', 'Access', 'Review'];
  let step = $state(0);

  // deployment
  let deploy = $state<'single' | 'custom'>(wc.cluster.targets.length && wc.cluster.targets[0] !== 'all' ? 'custom' : 'single');
  // first input
  let inType = $state<'file' | 'syslog'>('syslog');
  let inPath = $state('/var/log/syslog');
  let inListen = $state('0.0.0.0:5514');
  let addInput = $state(true);
  // access
  let adminUser = $state('admin');
  let adminPass = $state('');

  let saving = $state(false);
  let err = $state<string | null>(null);

  function toggleRole(r: string, on: boolean) {
    wc.cluster.targets = on
      ? [...wc.cluster.targets.filter((x) => x !== r), r]
      : wc.cluster.targets.filter((x) => x !== r);
  }

  function applyBeforeSave() {
    // deployment
    wc.cluster.targets = deploy === 'single' ? ['all'] : wc.cluster.targets.filter((r) => r !== 'all');
    // first input + a pipeline routing it to index + sigma
    if (addInput) {
      const id = inType === 'file' ? 'file_in' : 'syslog_in';
      const input =
        inType === 'file'
          ? { id, type: 'file', codec: { type: 'json' }, path: inPath }
          : { id, type: 'syslog', codec: { type: 'syslog' }, listen: inListen };
      if (!wc.inputs.some((i) => i.id === id)) wc.inputs = [...wc.inputs, input];
      if (!wc.pipelines.some((p) => p.from.includes(id))) {
        wc.pipelines = [...wc.pipelines, { id: 'main', from: [id], steps: [], route: [{ to: 'index' }, { to: 'sigma' }] }];
      }
    }
    // access
    if (wc.auth.enabled && adminUser.trim()) {
      const existing = wc.auth.users.find((u) => u.username === adminUser.trim());
      if (existing) {
        existing.roles = Array.from(new Set([...existing.roles, 'admin']));
        if (adminPass) existing.password = adminPass;
      } else {
        wc.auth.users = [...wc.auth.users, { username: adminUser.trim(), roles: ['admin'], password: adminPass || '' }];
      }
    }
  }

  async function finish() {
    saving = true;
    err = null;
    try {
      applyBeforeSave();
      // normalize empty passwords → null so the server keeps existing
      const c = structuredClone($state.snapshot(wc)) as PlatformConfig;
      for (const u of c.auth.users) {
        if (!u.password) u.password = null;
        if (!u.password_hash) u.password_hash = null;
      }
      c.edr.enrollment_tokens = [];
      const res = await api.saveConfig({ config: c });
      if (!res.ok) {
        err = res.report.errors[0] ?? 'validation failed';
        return;
      }
      ondone();
    } catch (e) {
      err = (e as Error).message;
    } finally {
      saving = false;
    }
  }

  const last = $derived(step === STEPS.length - 1);
</script>

<div class="wz-bg" role="presentation" onclick={oncancel} onkeydown={(e) => e.key === 'Escape' && oncancel()}>
  <div class="wz" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
    <div class="wzhead">
      <div class="brand">Sigil setup</div>
      <ol class="steps">
        {#each STEPS as s, i (s)}
          <li class:done={i < step} class:cur={i === step}>{s}</li>
        {/each}
      </ol>
    </div>

    <div class="wzbody">
      {#if step === 0}
        <h2>Welcome 👋</h2>
        <p class="muted">This guided setup writes a valid platform config in a few steps. You can fine-tune everything afterward in the Configuration Studio. Nothing is saved until the final step.</p>
      {:else if step === 1}
        <h2>Deployment</h2>
        <p class="muted">How should this node run?</p>
        <label class="opt"><input type="radio" bind:group={deploy} value="single" /> <b>Single node</b> — all roles in one process (monolith)</label>
        <label class="opt"><input type="radio" bind:group={deploy} value="custom" /> <b>Custom roles</b> — pick which roles this node runs</label>
        {#if deploy === 'custom'}
          <div class="chkrow">
            {#each meta.cluster_roles.filter((r) => r !== 'all') as r (r)}
              <label class="chk"><input type="checkbox" checked={wc.cluster.targets.includes(r)} onchange={(e) => toggleRole(r, e.currentTarget.checked)} /> {r}</label>
            {/each}
          </div>
        {/if}
      {:else if step === 2}
        <h2>Data input</h2>
        <div class="toggle-row"><Toggle bind:checked={addInput} label="Add a first data input" /></div>
        {#if addInput}
          <div class="opts">
            <label class="opt"><input type="radio" bind:group={inType} value="syslog" /> <b>Syslog</b> — receive over UDP/TCP</label>
            <label class="opt"><input type="radio" bind:group={inType} value="file" /> <b>File</b> — tail a log file</label>
          </div>
          {#if inType === 'syslog'}
            <Field label="Listen address"><input class="input" bind:value={inListen} /></Field>
          {:else}
            <Field label="File path"><input class="input" bind:value={inPath} /></Field>
          {/if}
          <p class="faint sm">A pipeline routing this input to indexing + Sigma detection will be created.</p>
        {/if}
      {:else if step === 3}
        <h2>Detections</h2>
        <div class="toggle-row"><Toggle bind:checked={wc.sigma.enabled} label="Enable the Sigma detection engine" /></div>
        {#if wc.sigma.enabled}
          <Field label="Rules directory"><input class="input" bind:value={wc.sigma.rules_dir} placeholder="configs/rules" /></Field>
        {/if}
        <div class="toggle-row" style="margin-top:14px"><Toggle bind:checked={wc.edr.enabled} label="Enable the EDR agent gateway" /></div>
        {#if wc.edr.enabled}
          <Field label="Gateway listen address"><input class="input" bind:value={wc.edr.listen} placeholder="0.0.0.0:50055" /></Field>
        {/if}
      {:else if step === 4}
        <h2>Access</h2>
        <div class="toggle-row"><Toggle bind:checked={wc.auth.enabled} label="Require authentication (recommended)" /></div>
        {#if wc.auth.enabled}
          <p class="muted sm">Create your first admin account.</p>
          <div class="rowgrid">
            <Field label="Admin username"><input class="input" bind:value={adminUser} /></Field>
            <Field label="Password"><input class="input" type="password" bind:value={adminPass} placeholder="choose a strong password" /></Field>
          </div>
        {/if}
      {:else if step === 5}
        <h2>Review</h2>
        <ul class="review">
          <li><b>Deployment</b>: {deploy === 'single' ? 'single node (all roles)' : wc.cluster.targets.join(', ') || 'no roles!'}</li>
          <li><b>Input</b>: {addInput ? `${inType} → ${inType === 'syslog' ? inListen : inPath}` : 'none'}</li>
          <li><b>Detections</b>: Sigma {wc.sigma.enabled ? 'on' : 'off'}, EDR {wc.edr.enabled ? 'on' : 'off'}</li>
          <li><b>Access</b>: auth {wc.auth.enabled ? `on, admin '${adminUser}'` : 'off'}</li>
        </ul>
        {#if err}<div class="errbox">{err}</div>{/if}
      {/if}
    </div>

    <div class="wzfoot">
      <button class="btn" onclick={oncancel}>Cancel</button>
      <span class="spacer"></span>
      {#if step > 0}<button class="btn" onclick={() => (step -= 1)}>Back</button>{/if}
      {#if !last}
        <button class="btn primary" onclick={() => (step += 1)}>Next</button>
      {:else}
        <button class="btn primary" onclick={finish} disabled={saving}>{saving ? 'Saving…' : 'Finish & save'}</button>
      {/if}
    </div>
  </div>
</div>

<style>
  .wz-bg { position: fixed; inset: 0; background: rgba(0,0,0,0.55); display: grid; place-items: center; z-index: 60; }
  .wz { background: var(--surface); border: 1px solid var(--border-2); border-radius: 10px; width: min(640px, 94vw); max-height: 88vh; display: grid; grid-template-rows: auto 1fr auto; overflow: hidden; }
  .wzhead { padding: 16px 20px; border-bottom: 1px solid var(--border); }
  .brand { font-weight: 600; color: var(--text-strong); margin-bottom: 10px; }
  .steps { list-style: none; display: flex; gap: 6px; margin: 0; padding: 0; flex-wrap: wrap; }
  .steps li { font-size: 11px; color: var(--faint); padding: 2px 8px; border-radius: 10px; border: 1px solid var(--border); }
  .steps li.done { color: var(--ok); border-color: var(--ok); }
  .steps li.cur { color: var(--text-strong); border-color: var(--accent); background: var(--surface-2); }
  .wzbody { padding: 20px; overflow: auto; display: grid; gap: 12px; align-content: start; }
  .wzbody h2 { font-size: 18px; text-transform: none; letter-spacing: 0; color: var(--text-strong); }
  .wzbody p { margin: 0; }
  .opts, .opt { display: grid; gap: 8px; }
  .opt { grid-auto-flow: column; justify-content: start; align-items: center; gap: 8px; font-size: 13px; }
  .toggle-row { display: flex; align-items: center; gap: 10px; }
  .rowgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .chkrow { display: flex; flex-wrap: wrap; gap: 12px; }
  .chk { display: flex; align-items: center; gap: 6px; font-size: 13px; }
  .review { margin: 0; padding-left: 18px; display: grid; gap: 6px; font-size: 13px; }
  .sm { font-size: 12px; }
  .wzfoot { display: flex; align-items: center; gap: 8px; padding: 14px 20px; border-top: 1px solid var(--border); }
  .spacer { flex: 1; }
</style>
