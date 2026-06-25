<script lang="ts">
  import { checkCapabilities, validCapability } from '../lib/capability';

  const example = JSON.stringify(
    { name: 'geoip_enricher', version: '1.2.0', kind: 'wasm', path: './geoip.wasm', capabilities: ['read:field:source.ip', 'enrich:geoip', 'net:egress'] },
    null,
    2,
  );

  let manifestText = $state(example);
  let granted = $state('read:field:source.ip\nenrich:geoip');
  let parsed = $state<{ name: string; version: string; capabilities: string[] } | null>(null);
  let parseError = $state<string | null>(null);

  let requested = $derived(parsed?.capabilities ?? []);
  let grantList = $derived(granted.split(/[\n,]/).map((s) => s.trim()).filter(Boolean));
  let denied = $derived(parsed ? checkCapabilities(requested, grantList) : []);
  let invalid = $derived(requested.filter((c) => !validCapability(c)));

  function parse() {
    try {
      const m = JSON.parse(manifestText);
      parsed = { name: m.name, version: m.version, capabilities: m.capabilities ?? [] };
      parseError = null;
    } catch (e) {
      parsed = null;
      parseError = (e as Error).message;
    }
  }
  parse();
</script>

<div class="page">
  <div class="head"><h1>Plugins</h1></div>

  <div class="card info">
    <h2>WASM sandbox · capability review</h2>
    <p class="muted">Tier-2 plugins run sandboxed under wasmtime with <b>deny-by-default</b> capabilities
      (DESIGN §12.2). Paste a plugin manifest and the granted capabilities to preview the host's decision —
      this mirrors <code>sigil plugin verify</code>.</p>
  </div>

  <div class="cols">
    <div class="card">
      <h2>Manifest (JSON)</h2>
      <textarea class="input mono" rows="11" bind:value={manifestText} oninput={parse}></textarea>
      {#if parseError}<div class="errbox">{parseError}</div>{/if}
    </div>
    <div class="card">
      <h2>Granted capabilities</h2>
      <textarea class="input mono" rows="5" bind:value={granted}></textarea>
      <div class="muted sm">one per line · forms: <code>net:egress</code>, <code>read:field:&lt;name&gt;</code>, <code>enrich:&lt;name&gt;</code></div>
    </div>
  </div>

  {#if parsed}
    <div class="card result" class:ok={denied.length === 0 && invalid.length === 0} class:bad={denied.length > 0 || invalid.length > 0}>
      <div class="rhead">
        <b>{parsed.name}</b> <span class="muted">v{parsed.version}</span>
        <span class="spacer"></span>
        {#if invalid.length}
          <span class="verdict bad">INVALID — {invalid.join(', ')}</span>
        {:else if denied.length === 0}
          <span class="verdict ok">✓ ALLOWED — all capabilities granted, plugin would instantiate</span>
        {:else}
          <span class="verdict bad">✗ DENIED — {denied.join(', ')} (instantiation refused)</span>
        {/if}
      </div>
      <div class="caps">
        {#each requested as c (c)}
          <span class="pill cap" class:granted={grantList.includes(c)} class:denied={denied.includes(c)}>{c}</span>
        {/each}
      </div>
    </div>
  {/if}
</div>

<style>
  .page { display: grid; gap: 16px; }
  .info p { margin: 0; max-width: 900px; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .result.ok { border-color: var(--ok); }
  .result.bad { border-color: var(--sev-high); }
  .rhead { display: flex; align-items: center; gap: 8px; }
  .verdict.ok { color: var(--ok); }
  .verdict.bad { color: var(--sev-high); }
  .caps { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
  .cap.granted { color: var(--ok); border-color: var(--ok); }
  .cap.denied { color: var(--sev-high); border-color: var(--sev-high); }
  .sm { font-size: 12px; margin-top: 6px; }
  @media (max-width: 900px) { .cols { grid-template-columns: 1fr; } }
</style>
