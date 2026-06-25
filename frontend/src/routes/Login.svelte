<script lang="ts">
  import { login } from '../lib/auth.svelte';

  let username = $state('');
  let password = $state('');
  let error = $state<string | null>(null);
  let busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    error = null;
    busy = true;
    try {
      await login(username, password);
    } catch (err) {
      error = (err as Error).message;
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <form class="card" onsubmit={submit}>
    <div class="brand"><strong>Sigil</strong> <span class="muted">SIEM</span></div>
    <p class="muted sub">Sign in to continue</p>
    <label>
      <span>Username</span>
      <!-- svelte-ignore a11y_autofocus -->
      <input class="input" bind:value={username} autocomplete="username" autofocus />
    </label>
    <label>
      <span>Password</span>
      <input class="input" type="password" bind:value={password} autocomplete="current-password" />
    </label>
    {#if error}<div class="errbox">{error}</div>{/if}
    <button class="btn primary" type="submit" disabled={busy || !username}>
      {busy ? 'Signing in…' : 'Sign in'}
    </button>
  </form>
</div>

<style>
  .wrap { display: grid; place-items: center; height: 100vh; }
  .card { width: 320px; display: grid; gap: 12px; padding: 28px; }
  .brand strong { color: var(--text-strong); font-size: 20px; }
  .sub { margin: -4px 0 8px; }
  label { display: grid; gap: 4px; font-size: 12px; color: var(--muted); }
  .btn.primary { margin-top: 6px; }
</style>
