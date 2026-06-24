// Typed fetch client for the Sigil API. Calls go to `/api/*` and are proxied to
// the backend (Vite dev proxy / nginx in prod) — see vite.config.ts.
// The full plan swaps this for an OpenAPI-generated client + @tanstack/svelte-query.

import type {
  AlertsResponse,
  AnalyticsResponse,
  CountResponse,
  IncidentsResponse,
  SearchResponse,
} from './types';

const BASE = '/api';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path, { headers: { accept: 'application/json' } });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.error) detail = body.error;
    } catch { /* ignore */ }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

const enc = encodeURIComponent;

export const api = {
  count: () => get<CountResponse>('/count'),
  search: (q: string, limit = 100) =>
    get<SearchResponse>(`/search?q=${enc(q)}&limit=${limit}`),
  sql: (q: string) => get<AnalyticsResponse>(`/sql?q=${enc(q)}`),
  query: (q: string) => get<AnalyticsResponse>(`/query?q=${enc(q)}`),
  alerts: (technique?: string, limit = 200) =>
    get<AlertsResponse>(
      `/alerts?limit=${limit}` + (technique ? `&technique=${enc(technique)}` : ''),
    ),
  incidents: () => get<IncidentsResponse>('/incidents'),
};
