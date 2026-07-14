<script lang="ts">
  import type { Snippet } from 'svelte';
  let {
    label,
    hint = '',
    error = '',
    children,
  }: { label: string; hint?: string; error?: string; children: Snippet } = $props();
</script>

<label class="field">
  <span class="flabel">{label}{#if hint}<span class="fhint">{hint}</span>{/if}</span>
  {@render children()}
  {#if error}<span class="ferr">{error}</span>{/if}
</label>

<style>
  .field { display: grid; gap: 5px; }
  .flabel { font-size: 12px; color: var(--muted); display: flex; align-items: baseline; gap: 8px; }
  .fhint { color: var(--faint); font-size: 11px; font-weight: 400; }
  .ferr { color: var(--sev-high); font-size: 11px; }
</style>
