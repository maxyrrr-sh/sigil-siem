// Token storage + 401 hook, kept dependency-free so the API client can import it
// without a cycle (the reactive auth store in auth.svelte.ts builds on top).

const KEY = 'sigil.token';

export function getToken(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function setToken(t: string | null): void {
  try {
    if (t) localStorage.setItem(KEY, t);
    else localStorage.removeItem(KEY);
  } catch {
    /* private mode — ignore */
  }
}

let onUnauthorized: (() => void) | null = null;

/** Register a callback invoked whenever the API sees a 401 (token expired/invalid). */
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

export function handleUnauthorized(): void {
  onUnauthorized?.();
}
