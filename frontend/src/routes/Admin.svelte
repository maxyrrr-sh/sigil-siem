<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import type { SystemInfo } from '../lib/types';
  import { theme, toggleTheme } from '../lib/theme.svelte';

  let sys = $state<SystemInfo | null>(null);
  onMount(async () => {
    try { sys = await api.system(); } catch { /* offline */ }
  });

  const planned = [
    ['RBAC', 'Users, roles, fine-grained permissions; server-enforced.'],
    ['Multi-tenant', 'Tenant isolation + a context switcher across all queries.'],
    ['SSO / SAML', 'OIDC Auth-Code + PKCE via Keycloak / Okta / Entra.'],
    ['API tokens', 'Scoped tokens for programmatic access.'],
    ['Audit log', 'Every config / rule / approval change, queryable.'],
  ];
</script>

<div class="page">
  <div class="head"><h1>Admin &amp; settings</h1></div>

  <div class="cols">
    <div class="card">
      <h2>Appearance</h2>
      <div class="setting">
        <span>Theme</span><span class="spacer"></span>
        <button class="btn" onclick={toggleTheme}>{theme.value === 'dark' ? '☾ Dark' : '☀ Light'}</button>
      </div>
      <div class="setting">
        <span>API base</span><span class="spacer"></span><code class="mono">/api</code>
      </div>
    </div>

    <div class="card">
      <h2>Node</h2>
      {#if sys}
        <div class="kv"><span class="k">roles</span><span>{sys.roles.join(', ')}</span></div>
        <div class="kv"><span class="k">transport</span><span>{sys.transport}</span></div>
        <div class="kv"><span class="k">nodes</span><span>{sys.nodes.join(', ')}</span></div>
        <div class="kv"><span class="k">rules</span><span>{sys.rule_count}</span></div>
        <div class="kv"><span class="k">retention</span><span>{sys.retention_hot} / {sys.retention_warm} / {sys.retention_cold}</span></div>
      {:else}
        <div class="faint">/system unavailable</div>
      {/if}
    </div>
  </div>

  <div class="card">
    <h2>Identity &amp; governance — planned</h2>
    <div class="planned">
      {#each planned as [name, blurb] (name)}
        <div class="prow"><span class="pname">{name}</span><span class="pblurb muted">{blurb}</span><span class="soon">F6 · backend §8</span></div>
      {/each}
    </div>
    <div class="muted sm">These require the auth + RBAC + audit endpoints (FRONTEND.md §8); the console enforces nothing client-side that the server doesn't.</div>
  </div>
</div>

<style>
  .page { display: grid; gap: 16px; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .setting { display: flex; align-items: center; gap: 10px; padding: 6px 0; }
  .kv { display: grid; grid-template-columns: 100px 1fr; gap: 8px; padding: 3px 0; }
  .kv .k { color: var(--faint); font-size: 11px; text-transform: uppercase; }
  .planned { display: grid; gap: 8px; }
  .prow { display: flex; align-items: center; gap: 12px; padding: 6px 0; border-bottom: 1px solid var(--border); }
  .pname { width: 120px; color: var(--text-strong); }
  .pblurb { flex: 1; font-size: 13px; }
  .soon { font-size: 10px; color: var(--faint); border: 1px solid var(--border); border-radius: 8px; padding: 1px 6px; }
  .sm { font-size: 12px; margin-top: 8px; }
  @media (max-width: 900px) { .cols { grid-template-columns: 1fr; } }
</style>
