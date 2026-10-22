/**
 * Response/request types used by the frontend-core pages (dashboard, events, sessions, hosts, settings)
 * that are not (yet) mirrored in `types.ts`. Shapes follow docs/api-contract.md and
 * backend/src/tokiwa/schemas/*.py. Keep field names identical to the backend.
 */
import type { ActorSession, ChannelKind, Incident, JobInfo, Severity, TkEvent } from "./types";

// ---------- users / tokens (schemas/system.py) ----------
export type Role = "admin" | "analyst" | "viewer";
export const ROLES: Role[] = ["admin", "analyst", "viewer"];

export interface User {
  id: string;
  username: string;
  role: Role;
  created_at: string;
  last_login?: string | null;
}

export interface UserCreate {
  username: string;
  password: string;
  role: Role;
}

export type ApiTokenScope = "ingest" | "gate" | "read";
export const API_TOKEN_SCOPES: ApiTokenScope[] = ["ingest", "gate", "read"];

export interface ApiTokenCreate {
  name: string;
  scopes: ApiTokenScope[];
}

// ApiToken itself lives in types.ts
export interface ApiTokenCreated {
  id: string;
  name: string;
  scopes: string[];
  prefix: string;
  created_at: string;
  last_used: string | null;
  revoked: boolean;
  /** Plain-text secret. Returned exactly once, on creation. */
  token: string;
}

// ---------- notify (schemas/response.py) ----------
export interface NotificationChannelIn {
  kind: ChannelKind;
  name: string;
  config: Record<string, unknown>;
  min_severity: Severity;
  enabled: boolean;
}

export interface NotifyTestResult {
  ok: boolean;
  error?: string | null;
}

// ---------- system (schemas/system.py) ----------
export interface AuditEntry {
  id: string;
  created_at: string;
  actor: string;
  action: string;
  target: string | null;
  details: Record<string, unknown>;
}

export interface SystemInfo {
  version: string;
  env: string;
  llm_provider: string;
  llm_available: boolean;
  database: string;
  detectors: number;
  jobs: JobInfo[];
}

// ---------- dashboard (routes/dashboard.py) ----------
export interface DashboardSummary {
  alerts_24h: { total: number; by_severity: Partial<Record<Severity, number>> };
  open_incidents: number;
  ai_sessions_24h: number;
  events_24h: number;
  llm_cost_today_usd: number;
  llm_budget_usd: number;
  pending_actions: number;
  kev_matches: number;
  top_sources: { ip: string; count: number; ai_score: number | null }[];
  top_rules: { rule_id: string; title: string; count: number }[];
  recent_incidents: Incident[];
}

export interface DashboardTimelineBucket {
  ts: string;
  events: number;
  alerts: number;
  ai_alerts: number;
}

export interface DashboardTimeline {
  buckets: DashboardTimelineBucket[];
}

// ---------- events (routes/events.py) ----------
export interface EventTimeline {
  buckets: { ts: string; total: number; by_kind: Record<string, number> }[];
}

// ---------- sessions (routes/sessions.py) ----------
export interface SessionTimelinePoint {
  /** Request time. ISO8601 per contract; epoch seconds/ms are tolerated by the UI. */
  t: string | number;
  path: string | null;
  status: number | null;
  /** Gap to the previous request in ms (null/0 for the first request). */
  gap_ms: number | null;
}

export interface SessionDetail {
  session: ActorSession;
  events: TkEvent[];
  timeline: SessionTimelinePoint[];
}

// ---------- hosts (routes/hosts.py, schemas/hosts.py) ----------
export interface HostSummary {
  host: string;
  ports_open: number;
  last_seen: string | null;
  deviations: number;
}

export interface HostPort {
  host: string;
  protocol: string;
  bind_ip: string;
  port: number;
  pid: number | null;
  process_name: string | null;
  first_seen: string;
  last_seen: string;
  open: boolean;
  allowed: boolean;
}

export interface PortBaseline {
  id: string;
  /** "*" applies to every host */
  host: string;
  protocol: string;
  port: number;
  /** null = any process */
  process_name: string | null;
  allow_public: boolean;
  note: string | null;
  created_at: string;
}

export interface PortBaselineIn {
  host?: string | null;
  protocol: string;
  port: number;
  process_name?: string | null;
  allow_public: boolean;
  note?: string | null;
}

// ---------- live stream (routes/stream.py) ----------
/** Topics relayed by GET /stream (see backend/src/tokiwa/bus.py). */
export type StreamTopic =
  | "event.ingested"
  | "alert.created"
  | "alert.updated"
  | "incident.created"
  | "incident.updated"
  | "action.proposed"
  | "action.updated"
  | "deception.tripped"
  | "intel.vuln_matched"
  | "intel.advisory"
  | "llm.call";
