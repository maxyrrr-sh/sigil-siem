<script lang="ts">
  // Loading / error / empty states in one tiny component.
  let {
    loading = false,
    error = null,
    empty = false,
    emptyText = 'Nothing to show',
  }: { loading?: boolean; error?: string | null; empty?: boolean; emptyText?: string } = $props();
</script>

{#if loading}
  <div class="skeleton">Loading…</div>
{:else if error}
  <div class="errbox">{error}</div>
{:else if empty}
  <div class="skeleton">{emptyText}</div>
{/if}
