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

// --- EDR fleet -------------------------------------------------------------
export interface Agent {
  agent_id: string;
  hostname: string;
  os: string;
  os_version: string;
  agent_version: string;
  enrolled_ts: number;
  last_seen: number;
  connected: boolean;
  isolated: boolean;
}
export interface EdrCommand {
  command_id: string;
  agent_id: string;
  command_type: string;
  params: Record<string, unknown>;
  status: string;
  issued_by: string;
  issued_ts: number;
  result_ok?: boolean;
  result_message?: string;
  result_bytes?: number;
  completed_ts?: number;
}
export interface AgentsResponse { agents: Agent[]; }
export interface AgentDetail { agent: Agent; commands: EdrCommand[]; }
export interface CommandsResponse { commands: EdrCommand[]; }
export interface EdrToken { prefix: string; label: string; created_ts: number; created_by?: string; }
export interface TokensResponse { tokens: EdrToken[]; }

// --- platform configuration ------------------------------------------------
export interface ValidationReport { ok: boolean; errors: string[]; warnings: string[]; }

// Structured config mirroring `sigil_config::Config` (secrets redacted on the wire).
export interface RouteTarget { to: string; }
export interface CodecConfig { type: string; [k: string]: unknown; }
export interface InputConfig { id: string; type: string; codec: CodecConfig; path?: string; listen?: string; [k: string]: unknown; }
export interface PipelineConfig { id: string; from: string[]; steps: unknown[]; route: RouteTarget[]; }
export interface Retention { hot: string; warm: string; cold: string; }
export interface IndexConfig { retention: Retention; path?: string | null; cold_path?: string | null; catalog_path?: string | null; }
export interface PagerDutyOutput { routing_key: string; url?: string | null; }
export interface JiraOutput { url: string; project: string; user: string; token: string; issue_type?: string | null; }
export interface MispOutput { url: string; api_key: string; }
export interface AlertOutputs {
  file?: string | null; webhook?: string | null; slack?: string | null;
  pagerduty?: PagerDutyOutput | null; jira?: JiraOutput | null; misp?: MispOutput | null;
}
export interface SigmaConfig { enabled: boolean; rulepacks: string[]; rules_dir?: string | null; outputs: AlertOutputs; }
export interface PluginConfig { name: string; kind: string; path: string; capabilities: string[]; }
// A detector's settings are a permissive bag (threshold, IOC file paths, …).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface DetectorRow { type: string; settings: Record<string, any>; }
export interface UserConfig { username: string; password_hash?: string | null; password?: string | null; roles: string[]; }
export interface AuthConfig { enabled: boolean; jwt_secret: string; token_ttl_secs: number; users: UserConfig[]; }
export interface EdrConfig { enabled: boolean; listen: string; tls_cert?: string | null; tls_key?: string | null; enrollment_tokens: string[]; }
export interface ClusterConfig { targets: string[]; nodes: string[]; shards?: number | null; replication?: number | null; object_store: unknown; transport: unknown; }
export interface PlatformConfig {
  version: number;
  cluster: ClusterConfig;
  inputs: InputConfig[];
  pipelines: PipelineConfig[];
  index: IndexConfig;
  sigma: SigmaConfig;
  auth: AuthConfig;
  data_dir?: string | null;
  ml_sidecar?: string | null;
  detectors: unknown;
  correlation: unknown;
  plugins: PluginConfig[];
  edr: EdrConfig;
}
export interface ConfigMeta {
  input_kinds: string[]; codecs: string[]; sinks: string[];
  roles: string[]; cluster_roles: string[]; transports: string[];
  edr_token_count: number; jwt_secret_set: boolean; users_with_password: string[];
}
export interface ConfigResponse {
  path: string;
  yaml: string;
  config?: PlatformConfig | null;
  meta?: ConfigMeta | null;
  report: ValidationReport;
}
export type ConfigInput = { yaml: string } | { config: PlatformConfig };
export interface ConfigValidateResponse { report: ValidationReport; }
export interface ConfigSaveResponse {
  ok: boolean;
  applied: boolean;
  report: ValidationReport;
  backup?: string;
  rules_reloaded?: number | null;
  restart_required?: boolean;
  message?: string;
}
export interface EdrActionBody {
  type: string;
  pid?: number;
  hash_sha256?: string;
  path?: string;
  max_bytes?: number;
  allowlist_cidrs?: string[];
}
