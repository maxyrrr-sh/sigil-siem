<script lang="ts">
  import type { SigilEvent } from '../lib/types';
  let { events, buckets = 40 }: { events: SigilEvent[]; buckets?: number } = $props();

  const W = 1000;
  const H = 90;

  let bars = $derived.by(() => {
    if (events.length === 0) return [] as { x: number; w: number; h: number }[];
    const ts = events.map((e) => e.ts);
    const min = Math.min(...ts);
    const max = Math.max(...ts);
    const span = Math.max(1, max - min);
    const counts = new Array(buckets).fill(0);
    for (const t of ts) {
      const i = Math.min(buckets - 1, Math.floor(((t - min) / span) * buckets));
      counts[i]++;
    }
    const peak = Math.max(1, ...counts);
    const bw = W / buckets;
    return counts.map((c, i) => ({
      x: i * bw,
      w: Math.max(1, bw - 1.5),
      h: (c / peak) * (H - 12),
    }));
  });
</script>

{#if events.length}
  <svg class="hist" viewBox="0 0 {W} {H}" preserveAspectRatio="none" role="img" aria-label="events over time">
    {#each bars as b (b.x)}
      <rect x={b.x} y={H - b.h} width={b.w} height={b.h} fill="var(--accent)" opacity="0.65" />
    {/each}
  </svg>
{/if}

<style>
  .hist { width: 100%; height: 90px; display: block; }
</style>
