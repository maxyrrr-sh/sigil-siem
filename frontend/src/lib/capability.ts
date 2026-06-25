// Client-side mirror of the WASM plugin capability model
// (crates/sigil-plugin-wasm/src/capability.rs) for the Plugins review screen.

export function validCapability(s: string): boolean {
  const t = s.trim();
  return t === 'net:egress' || t.startsWith('read:field:') || t.startsWith('enrich:');
}

/** Returns the requested capabilities denied by the granted set (deny-by-default). */
export function checkCapabilities(requested: string[], granted: string[]): string[] {
  const grantSet = new Set(granted.map((g) => g.trim()).filter(Boolean));
  return requested.map((r) => r.trim()).filter((r) => r && !grantSet.has(r));
}
