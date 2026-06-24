<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api } from '../lib/api';
  import { theme, toggleTheme } from '../lib/theme.svelte';

  let events = $state<number | null>(null);
  let alerts = $state<number | null>(null);
  let online = $state(true);
  let timer: ReturnType<typeof setInterval>;

  async function refresh() {
    try {
      const c = await api.count();
      events = c.events;
      alerts = c.alerts;
      online = true;
    } catch {
      online = false;
    }
  }

  onMount(() => {
    refresh();
    timer = setInterval(refresh, 5000);
  });
  onDestroy(() => clearInterval(timer));
</script>

<header class="top">
  <div class="brand">
    <strong>Sigil</strong>
    <span class="muted">SIEM · semantic + causal correlation</span>
  </div>
  <div class="spacer"></div>
  <div class="stat"><b>{events ?? '–'}</b> events</div>
  <div class="stat"><b>{alerts ?? '–'}</b> alerts</div>
  <div class="dot" class:on={online} title={online ? 'connected' : 'offline'}></div>
  <button class="btn" onclick={toggleTheme}>{theme.value === 'dark' ? '☾' : '☀'}</button>
</header>

<style>
  .top { display: flex; align-items: center; gap: 16px; padding: 0 16px; height: 100%; }
  .brand strong { color: var(--text-strong); font-size: 15px; }
  .brand .muted { margin-left: 10px; font-size: 12px; }
  .stat { font-size: 12px; color: var(--muted); }
  .stat b { color: var(--text-strong); }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--faint); }
  .dot.on { background: var(--ok); box-shadow: 0 0 6px var(--ok); }
</style>
