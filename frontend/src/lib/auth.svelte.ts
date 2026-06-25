// Reactive auth store: discovers whether auth is enabled, holds the current user,
// and drives login/logout. The raw token lives in token.ts (imported by the API
// client) so this module can build on top without an import cycle.

import { api } from './api';
import type { User } from './types';
import { getToken, setToken, setUnauthorizedHandler } from './token';

const ROLE_ORDER: Record<string, number> = { viewer: 0, analyst: 1, admin: 2 };

export const auth = $state<{
  enabled: boolean;
  user: User | null;
  ready: boolean;
}>({
  enabled: true,
  user: null,
  ready: false,
});

/** Discover auth state and resolve the current session. Call once at startup. */
export async function bootstrap(): Promise<void> {
  try {
    const h = await api.health();
    auth.enabled = !!h.auth_enabled;
  } catch {
    auth.enabled = true; // fail safe — require login if we can't tell
  }

  if (!auth.enabled) {
    auth.user = { username: 'anonymous', roles: ['admin'] };
    auth.ready = true;
    return;
  }

  if (getToken()) {
    try {
      auth.user = await api.me();
    } catch {
      setToken(null);
      auth.user = null;
    }
  }
  auth.ready = true;
}

export async function login(username: string, password: string): Promise<void> {
  const res = await api.login(username, password);
  setToken(res.token);
  auth.user = res.user;
}

export function logout(): void {
  setToken(null);
  auth.user = null;
}

/** True if the current user holds `role` or a more privileged one. */
export function can(role: 'viewer' | 'analyst' | 'admin'): boolean {
  if (!auth.user) return false;
  const need = ROLE_ORDER[role];
  return auth.user.roles.some((r) => (ROLE_ORDER[r] ?? -1) >= need);
}

// When any request 401s, drop the session so the app shows the login screen.
setUnauthorizedHandler(() => {
  setToken(null);
  auth.user = null;
});
