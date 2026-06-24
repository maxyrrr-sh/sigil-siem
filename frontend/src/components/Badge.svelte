<script lang="ts">
  import { severityColor } from '../lib/format';
  let { severity }: { severity?: string } = $props();
</script>

<span class="badge" style="color: {severityColor(severity)}; border-color: {severityColor(severity)}">
  {severity ?? 'unknown'}
</span>

<style>
  .badge {
    display: inline-block;
    border: 1px solid;
    border-radius: 10px;
    padding: 0 8px;
    font-size: 11px;
    line-height: 18px;
    text-transform: capitalize;
    opacity: 0.95;
  }
</style>
