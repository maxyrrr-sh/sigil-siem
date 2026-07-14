<script lang="ts" generics="T">
  import type { Snippet } from 'svelte';
  let {
    items = $bindable(),
    row,
    create,
    addLabel = 'Add',
    empty = 'None configured.',
  }: {
    items: T[];
    row: Snippet<[T, number]>;
    create: () => T;
    addLabel?: string;
    empty?: string;
  } = $props();

  function add() {
    items = [...items, create()];
  }
  function remove(i: number) {
    items = items.filter((_, j) => j !== i);
  }
</script>

<div class="list">
  {#if items.length === 0}
    <div class="lempty faint">{empty}</div>
  {/if}
  {#each items as item, i (i)}
    <div class="lrow">
      <div class="lbody">{@render row(item, i)}</div>
      <button class="rm" type="button" onclick={() => remove(i)} title="Remove" aria-label="Remove">×</button>
    </div>
  {/each}
  <button class="btn add" type="button" onclick={add}>+ {addLabel}</button>
</div>

<style>
  .list { display: grid; gap: 10px; }
  .lempty { font-size: 12px; padding: 4px 0; }
  .lrow { display: flex; gap: 10px; align-items: flex-start; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px; }
  .lbody { flex: 1; min-width: 0; }
  .rm {
    background: transparent; border: 0; color: var(--faint); cursor: pointer;
    font-size: 18px; line-height: 1; padding: 0 4px;
  }
  .rm:hover { color: var(--sev-high); }
  .add { justify-self: start; }
</style>
