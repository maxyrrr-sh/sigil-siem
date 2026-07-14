<script lang="ts">
  let {
    checked = $bindable(false),
    label = '',
    disabled = false,
  }: { checked?: boolean; label?: string; disabled?: boolean } = $props();
</script>

<button
  type="button"
  class="toggle"
  class:on={checked}
  {disabled}
  role="switch"
  aria-checked={checked}
  aria-label={label}
  onclick={() => (checked = !checked)}
>
  <span class="knob"></span>
</button>
{#if label}<span class="tlabel">{label}</span>{/if}

<style>
  .toggle {
    width: 38px; height: 22px; border-radius: 12px; padding: 0;
    border: 1px solid var(--border); background: var(--surface-2); cursor: pointer;
    position: relative; transition: background 0.12s, border-color 0.12s; flex: none;
  }
  .toggle.on { background: var(--accent); border-color: var(--accent); }
  .toggle:disabled { opacity: 0.5; cursor: not-allowed; }
  .knob {
    position: absolute; top: 2px; left: 2px; width: 16px; height: 16px;
    border-radius: 50%; background: var(--text-strong); transition: transform 0.12s;
  }
  .toggle.on .knob { transform: translateX(16px); background: #06101e; }
  .tlabel { font-size: 13px; color: var(--text); }
</style>
