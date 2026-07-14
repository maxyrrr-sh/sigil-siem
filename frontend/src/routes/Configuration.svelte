<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { ValidationReport, SystemInfo, PlatformConfig, ConfigMeta, InputConfig, PipelineConfig, UserConfig, PluginConfig, DetectorRow } from '../lib/types';
  import States from '../components/States.svelte';
  import Toggle from '../components/config/Toggle.svelte';
  import Field from '../components/config/Field.svelte';
  import ListEditor from '../components/config/ListEditor.svelte';
  import Wizard from '../components/config/Wizard.svelte';
  import { can } from '../lib/auth.svelte';
  import { router, navigate } from '../lib/router.svelte';

  const isAdmin = can('admin');

  let loading = $state(true);
  let error = $state<string | null>(null);
  let ready = $state(false);
  let path = $state('');
  let mode = $state<'form' | 'yaml'>('form');
  let showWizard = $state(false);

  // structured (form) state
  let config = $state<PlatformConfig | null>(null);
  let meta = $state<ConfigMeta | null>(null);
  let original = $state(''); // JSON snapshot for dirty tracking
  let newJwt = $state(''); // blank = keep existing
  let changingJwt = $state(false);

  // Detectors are stored as a permissive YAML value; edit them as typed rows.
  let detectors = $state<DetectorRow[]>([]);
  let origDetectors = $state('[]');

  function parseDetectors(v: unknown): DetectorRow[] {
    const out: DetectorRow[] = [];
    const push = (item: unknown) => {
      if (typeof item === 'string') out.push({ type: item, settings: {} });
      else if (item && typeof item === 'object') {
        for (const [type, settings] of Object.entries(item as Record<string, unknown>)) {
          out.push({ type, settings: (settings && typeof settings === 'object' ? settings : {}) as Record<string, unknown> });
        }
      }
    };
    if (Array.isArray(v)) v.forEach(push);
    else if (v && typeof v === 'object') push(v);
    return out;
  }
  function serializeDetectors(rows: DetectorRow[]): unknown {
    if (rows.length === 0) return null;
    return rows.map((r) => ({ [r.type]: Object.keys(r.settings).length ? r.settings : null }));
  }
  function newDetector(): DetectorRow {
    return { type: 'ioc', settings: {} };
  }

  function newPlugin(): PluginConfig {
    return { name: '', kind: 'wasm', path: '', capabilities: [] };
  }

  // raw (yaml) state
  let yaml = $state('');
  let yamlOriginal = $state('');

  let report = $state<ValidationReport | null>(null);
  let system = $state<SystemInfo | null>(null);

  let validating = $state(false);
  let saving = $state(false);
  let saveMsg = $state<string | null>(null);
  let saveOk = $state(false);
  let restartRequired = $state(false);
  let debounce: ReturnType<typeof setTimeout> | null = null;

  type SectionId = 'general' | 'inputs' | 'pipelines' | 'detections' | 'detectors' | 'edr' | 'access' | 'storage' | 'cluster' | 'plugins';
  const SECTIONS: { id: SectionId; label: string; icon: string; desc: string }[] = [
    { id: 'general', label: 'General', icon: '⚙', desc: 'Node basics — data directory and the optional ML sidecar.' },
    { id: 'inputs', label: 'Data Inputs', icon: '⇥', desc: 'Where telemetry comes from (file tails, syslog).' },
    { id: 'pipelines', label: 'Pipelines', icon: '⋔', desc: 'How inputs are enriched and routed to indexing, detection, and correlation.' },
    { id: 'detections', label: 'Detections', icon: '◈', desc: 'The Sigma engine, rule packs, and alert outputs.' },
    { id: 'detectors', label: 'Detectors', icon: '◉', desc: 'Custom detectors beyond Sigma (DGA, IOC matching).' },
    { id: 'edr', label: 'Response (EDR)', icon: '⛨', desc: 'The endpoint agent gateway and enrollment.' },
    { id: 'access', label: 'Access', icon: '⚿', desc: 'Authentication, JWT, and user roles (RBAC).' },
    { id: 'storage', label: 'Storage', icon: '⛁', desc: 'Tiered retention and index paths.' },
    { id: 'cluster', label: 'Cluster', icon: '⬡', desc: 'Node roles, transport, and sharding.' },
    { id: 'plugins', label: 'Plugins', icon: '⧉', desc: 'WASM plugins and their granted capabilities.' },
  ];
  let section = $state<SectionId>('general');
  let sec = $derived(SECTIONS.find((s) => s.id === section)!);

  // section → validation keyword mapping, for the rail status dots
  const SECTION_KEYS: Record<SectionId, string[]> = {
    general: ['version', 'data_dir', 'ml_sidecar'],
    inputs: ['input'],
    pipelines: ['pipeline', 'route', 'sink'],
    detections: ['sigma', 'rule'],
    detectors: ['detector'],
    edr: ['edr'],
    access: ['auth', 'user', 'jwt', 'password', 'role', 'credential'],
    storage: ['retention', 'index', 'cold', 'catalog'],
    cluster: ['cluster', 'transport', 'shard', 'node', 'target'],
    plugins: ['plugin', 'capabilit', 'wasm'],
  };
  function sectionStatus(id: SectionId): 'ok' | 'warn' | 'error' {
    if (!report) return 'ok';
    const keys = SECTION_KEYS[id];
    const hit = (list: string[]) => list.some((m) => keys.some((k) => m.toLowerCase().includes(k)));
    if (hit(report.errors)) return 'error';
    if (hit(report.warnings)) return 'warn';
    return 'ok';
  }

  let dirty = $derived(
    mode === 'yaml'
      ? yaml !== yamlOriginal
      : (config ? JSON.stringify($state.snapshot(config)) !== original : false) ||
        !!newJwt ||
        JSON.stringify($state.snapshot(detectors)) !== origDetectors,
  );
  let hasErrors = $derived(!!report && !report.ok);

  async function load() {
    loading = true;
    error = null;
    ready = false;
    saveMsg = null;
    changingJwt = false;
    newJwt = '';
    try {
      const [cfg, sys] = await Promise.all([api.getConfig(), api.system().catch(() => null)]);
      path = cfg.path;
      yaml = cfg.yaml;
      yamlOriginal = cfg.yaml;
      report = cfg.report;
      system = sys;
      config = cfg.config ?? null;
      meta = cfg.meta ?? null;
      detectors = config ? parseDetectors(config.detectors) : [];
      origDetectors = JSON.stringify(detectors);
      original = config ? JSON.stringify($state.snapshot(config)) : '';
      if (!config) mode = 'yaml'; // unparseable file → raw only
      const q = router.query.get('section') as SectionId | null;
      if (q && SECTIONS.some((s) => s.id === q)) section = q;
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
      // allow the reactive validator to run after the first paint
      setTimeout(() => (ready = true), 0);
    }
  }

  function payload() {
    if (mode === 'yaml') return { yaml };
    const c = structuredClone($state.snapshot(config)) as PlatformConfig;
    c.auth.jwt_secret = newJwt.trim() ? newJwt : '';
    for (const u of c.auth.users) {
      if (!u.password) u.password = null;
      if (!u.password_hash) u.password_hash = null;
    }
    c.edr.enrollment_tokens = []; // managed on the EDR page; server keeps existing
    c.detectors = serializeDetectors($state.snapshot(detectors));
    return { config: c };
  }

  async function validate() {
    validating = true;
    try {
      report = (await api.validateConfig(payload())).report;
    } catch (e) {
      report = { ok: false, errors: [(e as Error).message], warnings: [] };
    } finally {
      validating = false;
    }
  }

  function scheduleValidate() {
    saveMsg = null;
    if (debounce) clearTimeout(debounce);
    debounce = setTimeout(validate, 500);
  }

  // re-validate whenever the form model changes (form mode only)
  $effect(() => {
    if (mode !== 'form' || !config) return;
    JSON.stringify($state.snapshot(config)); // track deep changes
    JSON.stringify($state.snapshot(detectors));
    void newJwt;
    if (!ready) return;
    scheduleValidate();
  });

  async function save() {
    if (!isAdmin) return;
    saving = true;
    saveMsg = null;
    try {
      const res = await api.saveConfig(payload());
      if (res.ok) {
        await load(); // reload the redacted/normalized view from disk (clears saveMsg)
        saveOk = true;
        restartRequired = !!res.restart_required;
        saveMsg = res.message ?? 'Saved.';
      } else {
        report = res.report;
        saveOk = false;
        saveMsg = 'Not saved — fix the errors below.';
      }
    } catch (e) {
      saveOk = false;
      saveMsg = `error: ${(e as Error).message}`;
    } finally {
      saving = false;
    }
  }

  function pick(id: SectionId) {
    section = id;
    navigate(`/config?section=${id}`);
  }

  async function onWizardDone() {
    showWizard = false;
    await load();
    saveOk = true;
    saveMsg = 'Guided setup applied. Restart the node to activate.';
  }

  // --- small helpers for multi-selects -------------------------------------
  function toggleIn(arr: string[], v: string, on: boolean): string[] {
    const has = arr.includes(v);
    if (on && !has) return [...arr, v];
    if (!on && has) return arr.filter((x) => x !== v);
    return arr;
  }
  function pipeHasRoute(p: PipelineConfig, sink: string) {
    return p.route.some((r) => r.to === sink);
  }
  function setPipeRoute(p: PipelineConfig, sink: string, on: boolean) {
    p.route = on ? [...p.route.filter((r) => r.to !== sink), { to: sink }] : p.route.filter((r) => r.to !== sink);
  }
  function pipeEnrichers(p: PipelineConfig): string {
    for (const s of p.steps as Record<string, unknown>[]) {
      if (s && typeof s === 'object' && 'enrich' in s) {
        const e = s.enrich;
        const names = Array.isArray(e) ? e.map((x) => (typeof x === 'string' ? x : Object.keys(x)[0])) : [];
        return names.join(', ');
      }
    }
    return '';
  }
  function setPipeEnrichers(p: PipelineConfig, csv: string) {
    const names = csv.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
    const others = (p.steps as Record<string, unknown>[]).filter((s) => !(s && typeof s === 'object' && 'enrich' in s));
    p.steps = names.length ? [...others, { enrich: names }] : others;
  }

  function newInput(): InputConfig {
    return { id: '', type: 'file', codec: { type: 'json' }, path: '' };
  }
  function newPipeline(): PipelineConfig {
    return { id: '', from: [], steps: [], route: [{ to: 'index' }] };
  }
  function newUser(): UserConfig {
    return { username: '', roles: ['viewer'], password: '' };
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
      {#if config}
        <div class="seg mode">
          <button class:active={mode === 'form'} onclick={() => (mode = 'form')}>Form</button>
          <button class:active={mode === 'yaml'} onclick={() => (mode = 'yaml')}>YAML</button>
        </div>
      {/if}
      {#if isAdmin}
        <button class="btn" onclick={() => (showWizard = true)}>Guided setup</button>
      {/if}
      <button class="btn" onclick={load} disabled={loading}>Reload</button>
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
    <States {loading} {error} />

    {#if !loading && !error}
      <!-- status strip -->
      <div class="statusbar">
        {#if report}
          {#if report.ok}
            <span class="chip ok">✓ valid{report.warnings.length ? ` · ${report.warnings.length} warning(s)` : ''}</span>
          {:else}
            <span class="chip bad">✗ {report.errors.length} error(s)</span>
          {/if}
        {/if}
        {#if dirty}<span class="chip dirty">unsaved changes</span>{/if}
        <span class="path mono">{path}</span>
        {#if mode === 'form'}<span class="faint sm">Form-save rewrites the file as canonical YAML (comments dropped — use YAML mode to preserve them).</span>{/if}
      </div>

      {#if saveMsg}
        <div class="card banner" class:ok={saveOk} class:bad={!saveOk}>
          {saveMsg}{#if saveOk && restartRequired}<span class="restart"> · restart to fully apply</span>{/if}
        </div>
      {/if}

      {#if mode === 'yaml'}
        <div class="card editor-card">
          <textarea class="input mono editor" bind:value={yaml} oninput={scheduleValidate} spellcheck="false" wrap="off"></textarea>
          {#if report && (report.errors.length || report.warnings.length)}
            <div class="reports">
              {#each report.errors as e (e)}<div class="line err">✗ {e}</div>{/each}
              {#each report.warnings as w (w)}<div class="line warn">⚠ {w}</div>{/each}
            </div>
          {/if}
        </div>
      {:else if config && meta}
        <div class="studio">
          <!-- section rail -->
          <nav class="rail">
            {#each SECTIONS as s (s.id)}
              <button class="railitem" class:active={section === s.id} onclick={() => pick(s.id)}>
                <span class="ic">{s.icon}</span>
                <span class="rl">{s.label}</span>
                <span class="dot {sectionStatus(s.id)}"></span>
              </button>
            {/each}
          </nav>

          <!-- section body -->
          <div class="body">
            <div class="card">
              <div class="sechead"><h2 style="margin:0">{sec.label}</h2></div>
              <p class="muted secdesc">{sec.desc}</p>

              {#if section === 'general'}
                <div class="formgrid">
                  <Field label="Data directory" hint="durable store (triage + saved objects)">
                    <input class="input" bind:value={config.data_dir} placeholder="./data/store" />
                  </Field>
                  <Field label="ML sidecar URL" hint="optional; offline embedder used if empty">
                    <input class="input" bind:value={config.ml_sidecar} placeholder="http://127.0.0.1:50051" />
                  </Field>
                  <Field label="Config version"><input class="input" value={config.version} disabled /></Field>
                </div>

              {:else if section === 'inputs'}
                <ListEditor bind:items={config.inputs} create={newInput} addLabel="input" empty="No inputs configured.">
                  {#snippet row(input: InputConfig)}
                    <div class="rowgrid">
                      <Field label="ID"><input class="input" bind:value={input.id} placeholder="syslog_main" /></Field>
                      <Field label="Type">
                        <select class="input" bind:value={input.type}>
                          {#each meta!.input_kinds as k (k)}<option value={k}>{k}</option>{/each}
                        </select>
                      </Field>
                      <Field label="Codec">
                        <select class="input" bind:value={input.codec.type}>
                          {#each meta!.codecs as c (c)}<option value={c}>{c}</option>{/each}
                        </select>
                      </Field>
                      {#if input.type === 'file'}
                        <Field label="Path"><input class="input" bind:value={input.path} placeholder="/var/log/syslog" /></Field>
                      {:else if input.type === 'syslog'}
                        <Field label="Listen"><input class="input" bind:value={input.listen} placeholder="0.0.0.0:5514" /></Field>
                      {/if}
                    </div>
                  {/snippet}
                </ListEditor>

              {:else if section === 'pipelines'}
                <ListEditor bind:items={config.pipelines} create={newPipeline} addLabel="pipeline" empty="No pipelines configured.">
                  {#snippet row(pipe: PipelineConfig)}
                    <Field label="ID"><input class="input" bind:value={pipe.id} placeholder="main" /></Field>
                    <div class="sub-group">
                      <div class="grouplabel">From inputs</div>
                      <div class="chkrow">
                        {#if config!.inputs.length === 0}<span class="faint sm">add inputs first</span>{/if}
                        {#each config!.inputs as inp (inp.id)}
                          <label class="chk"><input type="checkbox" checked={pipe.from.includes(inp.id)} onchange={(e) => (pipe.from = toggleIn(pipe.from, inp.id, e.currentTarget.checked))} /> {inp.id || '(unnamed)'}</label>
                        {/each}
                      </div>
                    </div>
                    <div class="sub-group">
                      <div class="grouplabel">Route to</div>
                      <div class="chkrow">
                        {#each meta!.sinks as sink (sink)}
                          <label class="chk"><input type="checkbox" checked={pipeHasRoute(pipe, sink)} onchange={(e) => setPipeRoute(pipe, sink, e.currentTarget.checked)} /> {sink}</label>
                        {/each}
                      </div>
                    </div>
                    <div class="sub-group">
                      <div class="grouplabel">Enrichers</div>
                      <input class="input" value={pipeEnrichers(pipe)} onchange={(e) => setPipeEnrichers(pipe, e.currentTarget.value)} placeholder="geoip, threat_intel, entropy" />
                    </div>
                  {/snippet}
                </ListEditor>

              {:else if section === 'detections'}
                <div class="toggle-row"><Toggle bind:checked={config.sigma.enabled} label="Sigma detection engine" /></div>
                <div class="formgrid">
                  <Field label="Rules directory" hint="loaded recursively"><input class="input" bind:value={config.sigma.rules_dir} placeholder="configs/rules" /></Field>
                </div>
                <div class="sub-group">
                  <div class="grouplabel">Alert outputs</div>
                  <div class="formgrid">
                    <Field label="File (JSONL)"><input class="input" bind:value={config.sigma.outputs.file} placeholder="./alerts.jsonl" /></Field>
                    <Field label="Webhook URL"><input class="input" bind:value={config.sigma.outputs.webhook} placeholder="https://…" /></Field>
                    <Field label="Slack webhook"><input class="input" bind:value={config.sigma.outputs.slack} placeholder="https://hooks.slack.com/…" /></Field>
                  </div>
                  <div class="integrations">
                    <div class="intg">
                      <label class="chk small"><input type="checkbox" checked={!!config.sigma.outputs.pagerduty} onchange={(e) => (config!.sigma.outputs.pagerduty = e.currentTarget.checked ? { routing_key: '', url: null } : null)} /> PagerDuty</label>
                      {#if config.sigma.outputs.pagerduty}
                        <Field label="Routing key"><input class="input" bind:value={config.sigma.outputs.pagerduty.routing_key} /></Field>
                      {/if}
                    </div>
                    <div class="intg">
                      <label class="chk small"><input type="checkbox" checked={!!config.sigma.outputs.jira} onchange={(e) => (config!.sigma.outputs.jira = e.currentTarget.checked ? { url: '', project: '', user: '', token: '', issue_type: null } : null)} /> Jira</label>
                      {#if config.sigma.outputs.jira}
                        <div class="rowgrid">
                          <Field label="URL"><input class="input" bind:value={config.sigma.outputs.jira.url} placeholder="https://org.atlassian.net" /></Field>
                          <Field label="Project"><input class="input" bind:value={config.sigma.outputs.jira.project} placeholder="SEC" /></Field>
                          <Field label="User"><input class="input" bind:value={config.sigma.outputs.jira.user} /></Field>
                          <Field label="API token"><input class="input" type="password" bind:value={config.sigma.outputs.jira.token} /></Field>
                        </div>
                      {/if}
                    </div>
                    <div class="intg">
                      <label class="chk small"><input type="checkbox" checked={!!config.sigma.outputs.misp} onchange={(e) => (config!.sigma.outputs.misp = e.currentTarget.checked ? { url: '', api_key: '' } : null)} /> MISP</label>
                      {#if config.sigma.outputs.misp}
                        <div class="rowgrid">
                          <Field label="URL"><input class="input" bind:value={config.sigma.outputs.misp.url} /></Field>
                          <Field label="API key"><input class="input" type="password" bind:value={config.sigma.outputs.misp.api_key} /></Field>
                        </div>
                      {/if}
                    </div>
                  </div>
                </div>

              {:else if section === 'detectors'}
                <p class="muted sm">Custom detectors run after the Sigma engine on every event.</p>
                <ListEditor bind:items={detectors} create={newDetector} addLabel="detector" empty="No custom detectors.">
                  {#snippet row(d: DetectorRow)}
                    <Field label="Detector">
                      <select class="input" bind:value={d.type}>
                        <option value="dga">dga — algorithmically-generated domains</option>
                        <option value="ioc">ioc — hash / IP / domain indicator match</option>
                      </select>
                    </Field>
                    {#if d.type === 'dga'}
                      <Field label="Threshold" hint="bits/char; higher = stricter">
                        <input class="input" type="number" step="0.1" bind:value={d.settings.threshold} placeholder="3.5" />
                      </Field>
                    {:else if d.type === 'ioc'}
                      <div class="rowgrid">
                        <Field label="Hashes" hint="file path or list"><input class="input" bind:value={d.settings.hashes} placeholder="./iocs/hashes.txt" /></Field>
                        <Field label="IPs"><input class="input" bind:value={d.settings.ips} placeholder="./iocs/ips.txt" /></Field>
                        <Field label="Domains"><input class="input" bind:value={d.settings.domains} placeholder="./iocs/domains.txt" /></Field>
                      </div>
                    {/if}
                  {/snippet}
                </ListEditor>

              {:else if section === 'edr'}
                <div class="toggle-row"><Toggle bind:checked={config.edr.enabled} label="EDR agent gateway" /></div>
                <div class="formgrid">
                  <Field label="Listen address" hint="gRPC"><input class="input" bind:value={config.edr.listen} placeholder="0.0.0.0:50055" /></Field>
                  <Field label="TLS cert (PEM)"><input class="input" bind:value={config.edr.tls_cert} placeholder="/etc/sigil/edr-cert.pem" /></Field>
                  <Field label="TLS key (PEM)"><input class="input" bind:value={config.edr.tls_key} placeholder="/etc/sigil/edr-key.pem" /></Field>
                </div>
                <div class="secretline">
                  <span class="muted">Enrollment tokens: <b>{meta.edr_token_count}</b> configured</span>
                  <button class="linklike" onclick={() => navigate('/agents')}>Manage on the EDR page →</button>
                </div>

              {:else if section === 'access'}
                <div class="toggle-row"><Toggle bind:checked={config.auth.enabled} label="Require authentication (JWT + RBAC)" /></div>
                <div class="formgrid">
                  <Field label="Token lifetime (seconds)"><input class="input" type="number" bind:value={config.auth.token_ttl_secs} /></Field>
                  <Field label="JWT signing secret">
                    {#if changingJwt}
                      <input class="input" type="password" bind:value={newJwt} placeholder="new secret" />
                    {:else}
                      <div class="secretline">
                        <span class="mono faint">{meta.jwt_secret_set ? '•••••• (set)' : 'not set'}</span>
                        <button class="linklike" onclick={() => (changingJwt = true)}>Change</button>
                      </div>
                    {/if}
                  </Field>
                </div>
                <div class="sub-group">
                  <div class="grouplabel">Users</div>
                  <ListEditor bind:items={config.auth.users} create={newUser} addLabel="user" empty="No users — the API rejects all requests when auth is on.">
                    {#snippet row(u: UserConfig)}
                      <div class="rowgrid">
                        <Field label="Username"><input class="input" bind:value={u.username} /></Field>
                        <Field label="Password" hint={meta!.users_with_password.includes(u.username) ? 'blank keeps current' : 'set a password'}>
                          <input class="input" type="password" bind:value={u.password} placeholder={meta!.users_with_password.includes(u.username) ? '•••••• unchanged' : 'password'} />
                        </Field>
                      </div>
                      <div class="chkrow">
                        {#each meta!.roles as r (r)}
                          <label class="chk"><input type="checkbox" checked={u.roles.includes(r)} onchange={(e) => (u.roles = toggleIn(u.roles, r, e.currentTarget.checked))} /> {r}</label>
                        {/each}
                      </div>
                    {/snippet}
                  </ListEditor>
                </div>

              {:else if section === 'storage'}
                <div class="sub-group">
                  <div class="grouplabel">Retention</div>
                  <div class="formgrid">
                    <Field label="Hot (Tantivy)"><input class="input" bind:value={config.index.retention.hot} placeholder="7d" /></Field>
                    <Field label="Warm"><input class="input" bind:value={config.index.retention.warm} placeholder="30d" /></Field>
                    <Field label="Cold (Parquet)"><input class="input" bind:value={config.index.retention.cold} placeholder="365d" /></Field>
                  </div>
                </div>
                <div class="sub-group">
                  <div class="grouplabel">Paths</div>
                  <div class="formgrid">
                    <Field label="Hot index path"><input class="input" bind:value={config.index.path} placeholder="./data/index" /></Field>
                    <Field label="Cold path"><input class="input" bind:value={config.index.cold_path} placeholder="./data/cold" /></Field>
                    <Field label="Catalog path"><input class="input" bind:value={config.index.catalog_path} placeholder="./data/catalog.json" /></Field>
                  </div>
                </div>

              {:else if section === 'cluster'}
                <div class="sub-group">
                  <div class="grouplabel">Roles this node runs</div>
                  <div class="chkrow">
                    {#each meta.cluster_roles as r (r)}
                      <label class="chk"><input type="checkbox" checked={config.cluster.targets.includes(r)} onchange={(e) => (config!.cluster.targets = toggleIn(config!.cluster.targets, r, e.currentTarget.checked))} /> {r}</label>
                    {/each}
                  </div>
                </div>
                <div class="formgrid">
                  <Field label="Shards"><input class="input" type="number" bind:value={config.cluster.shards} placeholder="8" /></Field>
                  <Field label="Replication"><input class="input" type="number" bind:value={config.cluster.replication} placeholder="1" /></Field>
                </div>

              {:else if section === 'plugins'}
                <p class="muted sm">Tier-2 WASM plugins run sandboxed with deny-by-default capabilities (DESIGN §12). Preview a manifest's decision on the <button class="linklike" onclick={() => navigate('/plugins')}>Plugins page</button>.</p>
                <ListEditor bind:items={config.plugins} create={newPlugin} addLabel="plugin" empty="No plugins configured.">
                  {#snippet row(p: PluginConfig)}
                    <div class="rowgrid">
                      <Field label="Name"><input class="input" bind:value={p.name} placeholder="geoip_enricher" /></Field>
                      <Field label="Kind"><input class="input" bind:value={p.kind} placeholder="wasm" /></Field>
                      <Field label="Path"><input class="input" bind:value={p.path} placeholder="./plugins/geoip.wasm" /></Field>
                    </div>
                    <Field label="Capabilities" hint="comma-separated · read:field:x, enrich:x, net:egress">
                      <input class="input" value={p.capabilities.join(', ')} onchange={(e) => (p.capabilities = e.currentTarget.value.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean))} placeholder="read:field:source.ip, enrich:geoip" />
                    </Field>
                  {/snippet}
                </ListEditor>
              {/if}
            </div>

            <!-- section-relevant errors -->
            {#if report && (report.errors.length || report.warnings.length)}
              <div class="card reports">
                {#each report.errors as e (e)}<div class="line err">✗ {e}</div>{/each}
                {#each report.warnings as w (w)}<div class="line warn">⚠ {w}</div>{/each}
              </div>
            {/if}
          </div>

          <!-- running state -->
          <aside class="side">
            <div class="card">
              <h2>Running state</h2>
              {#if system}
                <div class="kv">
                  <span>roles</span><span>{system.roles.join(', ') || '—'}</span>
                  <span>inputs</span><span>{system.sources.length}</span>
                  <span>pipelines</span><span>{system.pipelines.length}</span>
                  <span>rules</span><span>{system.rule_count}</span>
                  <span>auth</span><span>{system.auth_enabled ? 'on' : 'off'}</span>
                </div>
                <div class="note faint">Reflects the last <b>started</b> config; save then restart to reconcile.</div>
              {:else}
                <div class="faint">system info unavailable</div>
              {/if}
            </div>
          </aside>
        </div>
      {/if}
    {/if}
  {/if}
</div>

{#if showWizard && meta && config}
  <Wizard {meta} base={config} ondone={onWizardDone} oncancel={() => (showWizard = false)} />
{/if}

<style>
  .page { display: grid; gap: 14px; }
  .head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
  .head h1 { margin: 0; }
  .sub { color: var(--muted); font-size: 13px; margin-top: 2px; }
  .hactions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .seg.mode button { font-size: 12px; }
  .statusbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .chip { font-size: 11px; padding: 1px 8px; border-radius: 10px; border: 1px solid var(--border); }
  .chip.ok { color: var(--ok); border-color: var(--ok); }
  .chip.bad { color: var(--sev-high); border-color: var(--sev-high); }
  .chip.dirty { color: var(--sev-medium); border-color: var(--sev-medium); }
  .path { color: var(--faint); font-size: 11px; }
  .sm { font-size: 11px; }
  .banner { font-size: 13px; }
  .banner.ok { border-color: var(--ok); color: var(--ok); }
  .banner.bad { border-color: var(--sev-high); color: var(--sev-high); }
  .restart { color: var(--sev-medium); }
  .editor-card { display: grid; gap: 10px; }
  .editor { width: 100%; min-height: 60vh; resize: vertical; line-height: 1.5; font-size: 12.5px; white-space: pre; }

  .studio { display: grid; grid-template-columns: 210px 1fr 240px; gap: 16px; align-items: start; }
  .rail { display: grid; gap: 2px; position: sticky; top: 0; }
  .railitem {
    display: flex; align-items: center; gap: 10px; width: 100%; text-align: left;
    background: transparent; border: 0; color: var(--muted); padding: 8px 10px;
    border-radius: 6px; cursor: pointer; font: inherit;
  }
  .railitem:hover { background: var(--surface-2); color: var(--text); }
  .railitem.active { background: var(--surface-2); color: var(--text-strong); box-shadow: inset 2px 0 0 var(--accent); }
  .railitem .ic { width: 16px; text-align: center; opacity: 0.8; }
  .railitem .rl { flex: 1; }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--border-2); }
  .dot.ok { background: var(--ok); }
  .dot.warn { background: var(--sev-medium); }
  .dot.error { background: var(--sev-high); }

  .body { display: grid; gap: 14px; min-width: 0; }
  .secdesc { margin: 2px 0 14px; font-size: 13px; }
  .formgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
  .rowgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
  .sub-group { margin-top: 16px; }
  .grouplabel { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: var(--faint); margin-bottom: 8px; }
  .toggle-row { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
  .chkrow { display: flex; flex-wrap: wrap; gap: 12px; }
  .chk { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text); }
  .chk.small { font-size: 12px; margin-bottom: 8px; }
  .integrations { display: grid; gap: 12px; margin-top: 14px; }
  .intg { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px; }
  .secretline { display: flex; align-items: center; gap: 12px; }
  .linklike { background: transparent; border: 0; color: var(--accent); cursor: pointer; font: inherit; padding: 0; }
  .linklike:hover { text-decoration: underline; }
  .preview { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-size: 12px; max-height: 300px; overflow: auto; }
  .reports { display: grid; gap: 4px; }
  .line { font-size: 12px; padding: 4px 8px; border-radius: 4px; font-family: var(--mono); }
  .line.err { color: var(--sev-high); background: color-mix(in srgb, var(--sev-high) 8%, transparent); }
  .line.warn { color: var(--sev-medium); background: color-mix(in srgb, var(--sev-medium) 8%, transparent); }
  .side { position: sticky; top: 0; }
  .kv { display: grid; grid-template-columns: 76px 1fr; gap: 4px 10px; font-size: 13px; }
  .kv span:nth-child(odd) { color: var(--faint); }
  .note { font-size: 11px; margin-top: 10px; }
  @media (max-width: 1100px) { .studio { grid-template-columns: 180px 1fr; } .side { display: none; } }
  @media (max-width: 760px) { .studio { grid-template-columns: 1fr; } .rail { position: static; grid-auto-flow: column; overflow-x: auto; } }
</style>
