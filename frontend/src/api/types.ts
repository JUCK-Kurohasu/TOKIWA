/**
 * TypeScript mirrors of backend Pydantic schemas (backend/src/tokiwa/schemas/*.py).
 * Keep field names identical. When a backend schema changes, update this file in the same PR.
 * Resource-specific response wrappers (dashboard stats etc.) live next to the page that uses them.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type ActorType = "human" | "automated_scanner" | "ai_agent" | "benign" | "unknown";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

// ---------- events ----------
export type EventKind =
  | "http"
  | "port_snapshot"
  | "port_change"
  | "connection"
  | "ids_alert"
  | "dns"
  | "process"
  | "auth"
  | "deception"
  | "llm_app"
  | "custom";

export interface Endpoint {
  ip?: string | null;
  port?: number | null;
  hostname?: string | null;
  geo_country?: string | null;
  asn?: number | null;
  asn_org?: string | null;
}

export interface HttpInfo {
  method?: string | null;
  scheme?: string | null;
  host?: string | null;
  path?: string | null;
  query?: string | null;
  headers?: Record<string, string>;
  header_order?: string[];
  user_agent?: string | null;
  referrer?: string | null;
  content_type?: string | null;
  request_body_size?: number | null;
  request_body?: string | null;
  status?: number | null;
  response_size?: number | null;
  response_content_type?: string | null;
  duration_ms?: number | null;
  http_version?: string | null;
}

export interface ProcessInfo {
  pid?: number | null;
  name?: string | null;
  exe?: string | null;
  cmdline?: string | null;
  username?: string | null;
}

export interface ListeningSocket {
  protocol: string;
  bind_ip: string;
  port: number;
  process?: ProcessInfo | null;
}

export interface TkEvent {
  id: string;
  timestamp: string;
  ingested_at?: string | null;
  kind: EventKind;
  dataset: string;
  sensor_id?: string | null;
  message?: string | null;
  host?: { name?: string | null; ip?: string[]; os?: string | null } | null;
  source?: Endpoint | null;
  destination?: Endpoint | null;
  http?: HttpInfo | null;
  network?: Record<string, unknown> | null;
  port?: { listeners?: ListeningSocket[]; change?: string | null; socket?: ListeningSocket | null } | null;
  ids?: Record<string, unknown> | null;
  deception?: Record<string, unknown> | null;
  llm_app?: Record<string, unknown> | null;
  process?: ProcessInfo | null;
  session_id?: string | null;
  asset_id?: string | null;
  tags?: string[];
  labels?: Record<string, string>;
  raw?: Record<string, unknown> | null;
}

// ---------- triage ----------
export type AttackStage =
  | "reconnaissance"
  | "resource_development"
  | "initial_access"
  | "execution"
  | "persistence"
  | "privilege_escalation"
  | "defense_evasion"
  | "credential_access"
  | "discovery"
  | "lateral_movement"
  | "collection"
  | "command_and_control"
  | "exfiltration"
  | "impact"
  | "none";

export type ActionType =
  | "block_ip"
  | "rate_limit"
  | "tarpit"
  | "deceive"
  | "deploy_canary"
  | "notify"
  | "webhook"
  | "nftables_block";

export interface RecommendedAction {
  action_type: ActionType;
  target: string;
  reason: string;
  ttl_minutes?: number | null;
}

export interface TriageResult {
  severity: Severity;
  category: string;
  confidence: number;
  actor_type: ActorType;
  ai_agent_likelihood: number;
  ai_agent_indicators: string[];
  attack_stage: AttackStage;
  mitre_techniques: string[];
  summary: string;
  rationale: string;
  evidence_ids: string[];
  next_steps: string[];
  recommended_actions: RecommendedAction[];
}

export interface TriageRecord {
  result: TriageResult;
  tier: string;
  model?: string | null;
  prompt_version: string;
  llm_call_id?: string | null;
  escalated: boolean;
  rejected_evidence_ids: string[];
}

// ---------- alerts / incidents / sessions ----------
export type AlertStatus = "new" | "triaging" | "triaged" | "acknowledged" | "resolved" | "false_positive";
export type AlertCategory =
  | "recon"
  | "scan"
  | "exploit_attempt"
  | "credential_attack"
  | "ai_agent"
  | "prompt_injection"
  | "deception"
  | "port_deviation"
  | "policy"
  | "vuln_exposure"
  | "ids"
  | "anomaly"
  | "other";

export interface Alert {
  id: string;
  created_at: string;
  updated_at: string;
  first_seen: string;
  last_seen: string;
  count: number;
  fingerprint: string;
  rule_id: string;
  detector: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  category: AlertCategory;
  mitre: string[];
  ai_score: number | null;
  source_ip: string | null;
  entities: Record<string, string>;
  evidence_event_ids: string[];
  tags: string[];
  details: Record<string, unknown>;
  status: AlertStatus;
  incident_id: string | null;
  triage: TriageRecord | null;
}

export interface AlertDetail extends Alert {
  evidence: TkEvent[];
}

export type IncidentStatus = "open" | "investigating" | "contained" | "resolved" | "false_positive";

export interface Incident {
  id: string;
  created_at: string;
  updated_at: string;
  first_seen: string;
  last_seen: string;
  title: string;
  summary: string;
  severity: Severity;
  status: IncidentStatus;
  category: AlertCategory;
  actor_type: ActorType;
  ai_score: number | null;
  source_ips: string[];
  alert_count: number;
  kill_chain: string[];
  mitre: string[];
  triage: TriageRecord | null;
  assignee: string | null;
  tags: string[];
}

export interface IncidentDetail extends Incident {
  alerts: Alert[];
  actions: ResponseAction[];
}

export interface ActorSession {
  id: string;
  source_ip: string;
  client_fingerprint: string;
  user_agent: string | null;
  first_seen: string;
  last_seen: string;
  request_count: number;
  error_count: number;
  unique_paths: number;
  features: Record<string, unknown>;
  ai_score: number;
  classification: ActorType;
  incident_id: string | null;
}

// ---------- response / deception / notify ----------
export type ActionStatus =
  | "proposed"
  | "approved"
  | "active"
  | "expired"
  | "reverted"
  | "rejected"
  | "failed";

export interface ResponseAction {
  id: string;
  created_at: string;
  updated_at: string;
  action_type: ActionType;
  target: string;
  params: Record<string, unknown>;
  reason: string;
  proposed_by: "rule" | "llm" | "user" | "policy";
  incident_id: string | null;
  alert_id: string | null;
  status: ActionStatus;
  reversible: boolean;
  ttl_minutes: number | null;
  approved_by: string | null;
  approved_at: string | null;
  executed_at: string | null;
  expires_at: string | null;
  reverted_at: string | null;
  result: Record<string, unknown>;
}

export type DeceptionKind = "honeytoken" | "decoy_path" | "ai_canary" | "labyrinth";

export interface DeceptionAsset {
  id: string;
  kind: DeceptionKind;
  name: string;
  path: string | null;
  token: string | null;
  content_template: string | null;
  description: string | null;
  enabled: boolean;
  created_at: string;
  trip_count: number;
  last_tripped: string | null;
}

export type ChannelKind = "webhook" | "slack" | "discord" | "email";

export interface NotificationChannel {
  id: string;
  kind: ChannelKind;
  name: string;
  config: Record<string, unknown>;
  min_severity: Severity;
  enabled: boolean;
  created_at: string;
}

// ---------- intel ----------
export interface SoftwareItem {
  vendor?: string | null;
  product: string;
  version?: string | null;
  cpe?: string | null;
  ecosystem?: string | null;
}

export type AssetKind = "host" | "service" | "web_app" | "llm_app" | "network_device" | "other";

export interface Asset {
  id: string;
  name: string;
  kind: AssetKind;
  hostname: string | null;
  ips: string[];
  software: SoftwareItem[];
  criticality: Severity;
  owner: string | null;
  tags: string[];
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface VulnRecord {
  id: string;
  aliases: string[];
  sources: string[];
  title: string | null;
  description: string | null;
  published: string | null;
  modified: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity: Severity | null;
  epss: number | null;
  epss_percentile: number | null;
  kev: boolean;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_ransomware: boolean | null;
  cwe: string[];
  affected: SoftwareItem[];
  references: string[];
}

export interface VulnMatch {
  id: string;
  vuln_id: string;
  asset_id: string;
  software: SoftwareItem | null;
  reason: string;
  confidence: number;
  status: "open" | "mitigated" | "accepted" | "false_positive";
  created_at: string;
}

export type Priority = "P1" | "P2" | "P3" | "P4";

export interface ProposedRule {
  kind: string;
  title: string;
  content: string;
  rationale: string;
}

export interface AdvisoryAnalysis {
  title: string;
  priority: Priority;
  summary: string;
  exploitation_status: string;
  affected_assets: string[];
  impact: string;
  mitigations: string[];
  detection_opportunities: string[];
  proposed_rules: ProposedRule[];
  references: string[];
  confidence: number;
}

export interface Advisory {
  id: string;
  created_at: string;
  vuln_ids: string[];
  title: string;
  priority: Priority;
  status: string;
  analysis: AdvisoryAnalysis;
  llm_call_id: string | null;
}

export interface IntelItem {
  id: string;
  source: string;
  url: string | null;
  title: string;
  summary: string | null;
  published: string | null;
  fetched_at: string;
  vuln_ids: string[];
  tags: string[];
  relevance: number | null;
}

export interface ResearchFinding {
  title: string;
  summary: string;
  cve_ids: string[];
  affected_products: string[];
  exploitation: string;
  relevance_to_assets: string;
  recommended_actions: string[];
  source_urls: string[];
}

export interface ResearchReport {
  id: string;
  created_at: string;
  topic: string;
  output: { findings: ResearchFinding[]; overall_assessment: string };
  citations: Record<string, unknown>[];
  llm_call_id: string | null;
}

// ---------- system ----------
export interface LLMCall {
  id: string;
  created_at: string;
  provider: string;
  model: string;
  tier: string;
  purpose: string;
  prompt_version: string;
  status: "ok" | "refused" | "error" | "budget_exceeded" | "invalid_output";
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  web_search_requests: number;
  cost_usd: number;
  latency_ms: number;
  related: Record<string, string>;
  error: string | null;
}

export interface LLMCallDetail extends LLMCall {
  request_redacted: string | null;
  response_text: string | null;
}

export interface Rule {
  id: string;
  kind: "sigma";
  title: string;
  content: string;
  status: "active" | "disabled" | "proposed" | "rejected";
  source: "builtin" | "user" | "llm";
  created_at: string;
  updated_at: string;
  hit_count: number;
  meta: Record<string, unknown>;
}

export interface DetectorInfo {
  id: string;
  name: string;
  description: string;
  category: string;
  kinds: string[];
  enabled: boolean;
  mitre: string[];
}

export interface JobInfo {
  name: string;
  interval_seconds: number;
  running: boolean;
  last_started: string | null;
  last_finished: string | null;
  last_error: string | null;
  run_count: number;
}

export interface ApiToken {
  id: string;
  name: string;
  scopes: string[];
  prefix: string;
  created_at: string;
  last_used: string | null;
  revoked: boolean;
}
