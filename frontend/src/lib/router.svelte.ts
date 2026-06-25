// Minimal hash router (static-host friendly — no server rewrites needed).
// Supports `#/path?a=b` deep links. SvelteKit routing is the planned upgrade.

function parse(): { path: string; query: URLSearchParams } {
  const raw = location.hash.replace(/^#/, '') || '/';
  const [path, qs] = raw.split('?');
  return { path: path || '/', query: new URLSearchParams(qs ?? '') };
}

export const router = $state(parse());

window.addEventListener('hashchange', () => {
  const p = parse();
  router.path = p.path;
  router.query = p.query;
});

/** Navigate to a path (optionally with a `?query` suffix). */
export function navigate(path: string): void {
  const target = path.replace(/^#/, '');
  if (location.hash.replace(/^#/, '') !== target) location.hash = target;
}
