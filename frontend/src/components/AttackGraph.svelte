<script lang="ts">
  import type { Incident } from '../lib/types';

  let { incident }: { incident: Incident } = $props();

  const NODE_W = 210;
  const NODE_H = 58;
  const GAP = 40;
  const PAD = 16;
  const Y = 44;

  let steps = $derived(incident.chain);
  let width = $derived(PAD * 2 + steps.length * NODE_W + Math.max(0, steps.length - 1) * GAP);
  let height = 132;

  function x(i: number): number {
    return PAD + i * (NODE_W + GAP);
  }
</script>

<div class="scroll graph-wrap">
  <svg viewBox="0 0 {width} {height}" width={width} {height} role="img" aria-label="reconstructed attack graph">
    <defs>
      <marker id="arr" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
        <path d="M0,0 L9,4.5 L0,9 z" fill="var(--border-2)" />
      </marker>
    </defs>

    {#each steps as step, i (step.event_id + i)}
      {#if i > 0}
        <line
          x1={x(i) - GAP} y1={Y + NODE_H / 2}
          x2={x(i)} y2={Y + NODE_H / 2}
          stroke="var(--border-2)" stroke-width="2" marker-end="url(#arr)" />
      {/if}

      <text class="tactic-lbl" x={x(i)} y={Y - 10}>{step.tactic ?? '—'}</text>
      <rect x={x(i)} y={Y} width={NODE_W} height={NODE_H} rx="7"
        fill="var(--surface-2)" stroke="var(--border-2)" />
      <text class="node-step" x={x(i) + 12} y={Y + 16}>{i + 1}. {step.label}</text>
      {#if step.technique}
        <text class="node-tech" x={x(i) + 12} y={Y + 38}>{step.technique}</text>
      {/if}
      <text class="node-anom" x={x(i) + NODE_W - 12} y={Y + 38}>
        anomaly {step.anomaly.toFixed(2)}
      </text>
    {/each}
  </svg>
</div>

<style>
  .graph-wrap { padding-bottom: 6px; }
  svg { display: block; }
  text { fill: var(--text); font-family: var(--sans); }
  .tactic-lbl { fill: var(--tactic); font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; }
  .node-step { font-size: 12px; fill: var(--text-strong); }
  .node-tech { font-size: 12px; fill: var(--accent-2); font-family: var(--mono); }
  .node-anom { font-size: 10px; fill: var(--faint); text-anchor: end; }
</style>
