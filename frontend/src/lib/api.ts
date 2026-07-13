// Typed fetch client for the Sigil API. Calls go to `/api/v1/*` and are proxied
// to the backend (Vite dev proxy / nginx in prod) — see vite.config.ts.
// A bearer token (when present) is attached automatically; a 401 triggers the
// registered unauthorized handler so the app can drop to the login screen.

import type {
  AgentDetail,
  AgentsResponse,
  AlertsResponse,
  AnalyticsResponse,
  AttackCoverage,
  CommandsResponse,
  CountResponse,
  EdrActionBody,
  EdrCommand,
  EvalReport,
  FieldsResponse,
  HealthResponse,
  IncidentsResponse,
  LoginResponse,
  RuleTestResult,
  RulesResponse,
  SavedListResponse,
  SavedObject,
  SearchResponse,
  SystemInfo,
  User,
} from './types';
import { getToken, handleUnauthorized } from './token';

const BASE = '/api/v1';

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

async function req<T>(method: Method, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { accept: 'application/json' };
  const tok = getToken();
  if (tok) headers.authorization = `Bearer ${tok}`;
  if (body !== undefined) headers['content-type'] = 'application/json';

  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401) handleUnauthorized();
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const b = await res.json();
      if (b?.error) detail = b.error;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const get = <T>(p: string) => req<T>('GET', p);
const enc = encodeURIComponent;

export const api = {
  // health + auth
  health: () => get<HealthResponse>('/health'),
  login: (username: string, password: string) =>
    req<LoginResponse>('POST', '/auth/login', { username, password }),
  me: () => get<User>('/me'),

  // read
  count: () => get<CountResponse>('/count'),
  search: (q: string, limit = 100) => get<SearchResponse>(`/search?q=${enc(q)}&limit=${limit}`),
  searchFields: () => get<FieldsResponse>('/search/fields'),
  searchHistogram: (q: string, interval = '1h') =>
    get<AnalyticsResponse>(`/search/histogram?q=${enc(q)}&interval=${enc(interval)}`),
  sql: (q: string) => get<AnalyticsResponse>(`/sql?q=${enc(q)}`),
  query: (q: string) => get<AnalyticsResponse>(`/query?q=${enc(q)}`),
  alerts: (technique?: string, limit = 200) =>
    get<AlertsResponse>(`/alerts?limit=${limit}` + (technique ? `&technique=${enc(technique)}` : '')),
  incidents: () => get<IncidentsResponse>('/incidents'),
  rules: () => get<RulesResponse>('/rules'),
  attackCoverage: () => get<AttackCoverage>('/attack/coverage'),
  system: () => get<SystemInfo>('/system'),
  evaluate: (seed = 1) => get<EvalReport>(`/eval?seed=${seed}`),

  // alert triage (mutations)
  patchAlert: (fp: string, patch: { status?: string; assignee?: string; note?: string }) =>
    req('PATCH', `/alerts/${enc(fp)}`, patch),
  bulkPatchAlerts: (fingerprints: string[], patch: { status?: string; assignee?: string; note?: string }) =>
    req<{ updated: number }>('PATCH', '/alerts', { fingerprints, ...patch }),

  // rules CRUD + test
  ruleCreate: (yaml: string) => req<{ rule_id: string; rules: number }>('POST', '/rules', { yaml }),
  ruleUpdate: (id: string, yaml: string) =>
    req<{ rule_id: string; rules: number }>('PUT', `/rules/${enc(id)}`, { yaml }),
  ruleDelete: (id: string) => req<{ deleted: string }>('DELETE', `/rules/${enc(id)}`),
  ruleTest: (id: string, cases: RuleTestCase[], yaml?: string) =>
    req<RuleTestResult>('POST', `/rules/${enc(id)}/test`, { yaml, cases }),

  // saved objects
  savedList: (kind: string) => get<SavedListResponse>(`/saved/${enc(kind)}`),
  savedCreate: (kind: string, name: string, body: unknown) =>
    req<SavedObject>('POST', `/saved/${enc(kind)}`, { name, body }),
  savedUpdate: (kind: string, id: string, name: string, body: unknown) =>
    req<SavedObject>('PUT', `/saved/${enc(kind)}/${enc(id)}`, { name, body }),
  savedDelete: (kind: string, id: string) => req<void>('DELETE', `/saved/${enc(kind)}/${enc(id)}`),

  // live alert stream (SSE). EventSource can't set headers, so token rides the query.
  streamAlerts: (): EventSource => {
    const tok = getToken();
    const qs = tok ? `?token=${enc(tok)}` : '';
    return new EventSource(BASE + '/stream/alerts' + qs);
  },

  // EDR fleet
  edrAgents: () => get<AgentsResponse>('/edr/agents'),
  edrAgent: (id: string) => get<AgentDetail>(`/edr/agents/${enc(id)}`),
  edrAction: (id: string, body: EdrActionBody) =>
    req<EdrCommand>('POST', `/edr/agents/${enc(id)}/actions`, body),
  edrCommands: (agent?: string) =>
    get<CommandsResponse>('/edr/commands' + (agent ? `?agent=${enc(agent)}` : '')),
  edrIssueToken: (label?: string) =>
    req<{ token: string; label: string }>('POST', '/edr/enroll-tokens', { label }),
  streamAgents: (): EventSource => {
    const tok = getToken();
    const qs = tok ? `?token=${enc(tok)}` : '';
    return new EventSource(BASE + '/edr/stream/agents' + qs);
  },
};

export type RuleTestCase = {
  name: string;
  message?: string;
  fields?: Record<string, string>;
  expect_match: boolean;
};
