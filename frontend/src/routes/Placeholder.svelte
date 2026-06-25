<script lang="ts">
  let { title, phase, blurb }: { title: string; phase: string; blurb: string } = $props();
</script>

<div class="page">
  <div class="head"><h1>{title}</h1><span class="pill">{phase}</span></div>
  <div class="card placeholder">
    <p>{blurb}</p>
  </div>
</div>

<style>
  .page { display: grid; gap: 16px; }
  .head { display: flex; align-items: center; gap: 12px; }
  .placeholder { max-width: 720px; }
  .placeholder p { margin: 0 0 10px; }
</style>
