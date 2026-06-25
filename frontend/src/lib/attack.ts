// ATT&CK tactic mapping — mirrors crates/sigil-correlate/src/attack.rs so the
// UI can group techniques into tactics without an extra API call.

export const TACTICS = [
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
] as const;

export function tacticFor(technique?: string | null): string {
  if (!technique) return 'unknown';
  const t = technique.toUpperCase();
  const has = (...p: string[]) => p.some((x) => t.startsWith(x));
  if (has('T1110', 'T1003', 'T1552')) return 'credential-access';
  if (has('T1548', 'T1068', 'T1078')) return 'privilege-escalation';
  if (has('T1059', 'T1203')) return 'execution';
  if (has('T1071', 'T1572', 'T1105')) return 'command-and-control';
  if (has('T1041', 'T1048')) return 'exfiltration';
  if (has('T1021', 'T1210')) return 'lateral-movement';
  return 'unknown';
}
