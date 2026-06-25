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

export interface RuleInfo {
  rule_id: string;
  title: string;
  severity: string;
  technique?: string | null;
  tags: string[];
}

export interface CountResponse { events: number; alerts: number; }
export interface RulesResponse { count: number; rules: RuleInfo[]; }

// --- auth ---
export interface User { username: string; roles: string[]; }
export interface LoginResponse {
  token: string;
  token_type: string;
  expires_in: number;
  user: User;
}
export interface HealthResponse { status: string; auth_enabled: boolean; persistence: boolean; }

// --- alert triage (durable) ---
export type TriageStatus = 'open' | 'acknowledged' | 'closed';
export interface Note { ts: number; author: string; text: string; }
export interface AlertRecord {
  fingerprint: string;
  alert: Alert;
  status: TriageStatus;
  assignee?: string | null;
  notes: Note[];
  created_ts: number;
  updated_ts: number;
}

// --- saved objects ---
export interface SavedObject {
  kind: string;
  id: string;
  name: string;
  owner?: string | null;
  updated_ts: number;
  body: unknown;
}
export interface SavedListResponse { kind: string; objects: SavedObject[]; }

// --- search helpers / rule test / attack coverage ---
export interface FieldInfo { name: string; type: string; nullable: boolean; }
export interface FieldsResponse { fields: FieldInfo[]; }
export interface RuleTestResult { passed: boolean; cases: number; failures: string[]; }
export interface TechniqueCoverage {
  technique: string;
  tactic: string;
  covered: boolean;
  observed: boolean;
}
export interface AttackCoverage {
  covered: number;
  observed: number;
  techniques: TechniqueCoverage[];
}

export interface SourceInfo { id: string; kind: string; codec: string; }
export interface PipelineInfo { id: string; from: string[]; route: string[]; }
export interface SystemInfo {
  roles: string[];
  transport: string;
  nodes: string[];
  shards: number;
  replication: number;
  sources: SourceInfo[];
  pipelines: PipelineInfo[];
  retention_hot: string;
  retention_warm: string;
  retention_cold: string;
  index_path: string;
  cold_path: string;
  rule_count: number;
  auth_enabled?: boolean;
  persistence?: boolean;
}

export interface VariantResult {
  variant: string;
  ari: number;
  nmi: number;
  alert_reduction: number;
  technique_f1: number;
  chain_similarity: number;
  incidents: number;
}
export interface EvalReport { scenario: string; alerts: number; rows: VariantResult[]; }
export interface SearchResponse { count: number; events: SigilEvent[]; }
export interface AlertsResponse { count: number; alerts: AlertRecord[]; }
export interface IncidentsResponse { count: number; incidents: Incident[]; }
export interface AnalyticsResponse {
  sql: string;
  columns: string[];
  count: number;
  rows: Record<string, unknown>[];
}
