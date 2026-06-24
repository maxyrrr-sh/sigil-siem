// TypeScript mirror of the Sigil backend contracts (sigil-core / sigil-correlate).
// In the full plan these are generated from OpenAPI + validated with Zod.

export interface EntityRef {
  kind: string;
  id: string;
  name?: string | null;
}

export type OcsfClass = string | Record<string, number>;

export interface SigilEvent {
  id: string;
  ts: number;
  ingest_ts: number;
  ocsf_class: OcsfClass;
  tenant: string;
  severity: string;
  host?: EntityRef | null;
  actor?: EntityRef | null;
  target?: EntityRef | null;
  message: string;
  fields: Record<string, unknown>;
  template_id?: number | null;
  labels?: string[];
  raw?: string | number[];
}

export interface Alert {
  rule_id: string;
  title: string;
  severity: string;
  technique?: string | null;
  events: string[];
  ts: number;
}

export interface IncidentStep {
  event_id: string;
  label: string;
  ts: number;
  tactic?: string | null;
  technique?: string | null;
  anomaly: number;
}

export interface Incident {
  id: number;
  events: string[];
  chain: IncidentStep[];
  tactics: string[];
  techniques: string[];
  confidence: number;
  explanation: string[];
}

export interface CountResponse { events: number; alerts: number; }
export interface SearchResponse { count: number; events: SigilEvent[]; }
export interface AlertsResponse { count: number; alerts: Alert[]; }
export interface IncidentsResponse { count: number; incidents: Incident[]; }
export interface AnalyticsResponse {
  sql: string;
  columns: string[];
  count: number;
  rows: Record<string, unknown>[];
}
