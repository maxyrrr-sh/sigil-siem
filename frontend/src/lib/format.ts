import type { OcsfClass } from './types';

/** OCSF class → display string (handles the `{other: 1008}` newtype variant). */
export function className(c: OcsfClass | undefined): string {
  if (!c) return 'unknown';
  return typeof c === 'string' ? c : Object.keys(c)[0];
}

/** Epoch-microseconds → local time string. */
export function fmtTime(micros: number): string {
  if (!micros) return '';
  const d = new Date(micros / 1000);
  return d.toLocaleString(undefined, { hour12: false });
}

/** CSS variable for a severity colour. */
export function severityColor(sev: string | undefined): string {
  const key = (sev ?? 'unknown').toLowerCase();
  return `var(--sev-${key}, var(--sev-unknown))`;
}

export function confidenceLabel(c: number): string {
  if (c >= 0.8) return 'high';
  if (c >= 0.5) return 'medium';
  return 'low';
}
