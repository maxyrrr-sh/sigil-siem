<script lang="ts">
  let {
    data,
    max,
    fmt = (v: number) => String(v),
    color = 'var(--accent)',
  }: {
    data: { label: string; value: number }[];
    max?: number;
    fmt?: (v: number) => string;
    color?: string;
  } = $props();

  let peak = $derived(max ?? Math.max(1, ...data.map((d) => d.value)));
  const pct = (v: number) => Math.max(0, Math.min(100, (v / peak) * 100));
</script>

<div class="bars">
  {#each data as d (d.label)}
    <div class="row">
      <span class="lbl" title={d.label}>{d.label}</span>
      <span class="track"><span class="fill" style="width:{pct(d.value)}%; background:{color}"></span></span>
      <span class="val">{fmt(d.value)}</span>
    </div>
  {/each}
  {#if data.length === 0}<div class="faint">no data</div>{/if}
</div>

<style>
  .bars { display: grid; gap: 6px; }
  .row { display: grid; grid-template-columns: 140px 1fr 56px; gap: 10px; align-items: center; }
  .lbl { font-family: var(--mono); font-size: 12px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .track { height: 14px; background: var(--bg); border-radius: 4px; overflow: hidden; border: 1px solid var(--border); }
  .fill { display: block; height: 100%; opacity: 0.8; border-radius: 4px; }
  .val { text-align: right; font-family: var(--mono); font-size: 12px; color: var(--muted); }
</style>
