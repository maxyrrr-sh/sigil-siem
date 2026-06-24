// Minimal hash router (static-host friendly — no server rewrites needed).
// SvelteKit routing is the planned upgrade for the full app.

function parse(): string {
  const h = location.hash.replace(/^#/, '');
  return h === '' ? '/' : h;
}

export const router = $state({ path: parse() });

window.addEventListener('hashchange', () => {
  router.path = parse();
});

export function navigate(path: string): void {
  if (location.hash.replace(/^#/, '') !== path) location.hash = path;
  else router.path = path;
}
