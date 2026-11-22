/**
 * Request/response types used by the ops pages (alerts / incidents / response / deception) that are not
 * in the shared types.ts. Mirrors backend/src/tokiwa/schemas/{alerts,response}.py request models.
 * Kept in a separate file so the shared types.ts stays untouched during parallel development.
 */
import type {
  ActionStatus,
  ActionType,
  ActorType,
  AlertCategory,
  AlertStatus,
  DeceptionKind,
  IncidentStatus,
} from "./types";

export type ActionProposer = "rule" | "llm" | "user" | "policy";

/** POST /alerts/{id}/triage?tier= */
export type RetriageTier = "fast" | "deep";

/** PATCH /alerts/{id} — schemas.alerts.AlertUpdate */
export interface AlertUpdate {
  status?: AlertStatus;
  tags?: string[];
}

/** PATCH /incidents/{id} — schemas.alerts.IncidentUpdate */
export interface IncidentUpdate {
  status?: IncidentStatus;
  assignee?: string | null;
  tags?: string[];
}

/** POST /response/actions — schemas.response.ActionProposal */
export interface ActionProposal {
  action_type: ActionType;
  target: string;
  params?: Record<string, unknown>;
  reason: string;
  ttl_minutes?: number | null;
  incident_id?: string | null;
  alert_id?: string | null;
  proposed_by?: ActionProposer;
}

/** Optional part of reject / revert (audit #63): do not re-propose this type + target. */
export interface SuppressOptions {
  suppress_hours?: number;
  suppress_permanent?: boolean;
}

/** POST /response/actions/{id}/reject */
export interface ActionRejectBody extends SuppressOptions {
  reason?: string;
}

/** POST /response/actions/{id}/revert */
export interface ActionRevertBody extends SuppressOptions {
  reason?: string;
}

/** schemas.suppressions.SuppressionMode */
export type SuppressionMode = "suppress" | "manual_only";

/** GET /response/suppressions — schemas.suppressions.ResponseSuppression */
export interface ResponseSuppression {
  id: string;
  created_at: string;
  updated_at: string;
  action_type: ActionType;
  target: string;
  mode: SuppressionMode;
  reason: string;
  created_by: string;
  source_action_id: string | null;
  expires_at: string | null;
  lifted_at: string | null;
  lifted_by: string | null;
  hits: number;
  last_hit_at: string | null;
  active: boolean;
}

/** POST /deception/assets — schemas.response.DeceptionAssetIn (PATCH accepts a subset) */
export interface DeceptionAssetIn {
  kind: DeceptionKind;
  name: string;
  path?: string | null;
  token?: string | null;
  content_template?: string | null;
  description?: string | null;
  enabled?: boolean;
}

/** GET /deception/preview/{id} */
export interface DeceptionPreview {
  path: string;
  content_type: string;
  body: string;
}

export const ALERT_STATUSES: AlertStatus[] = [
  "new",
  "triaging",
  "triaged",
  "acknowledged",
  "resolved",
  "false_positive",
];

export const ALERT_CATEGORIES: AlertCategory[] = [
  "ai_agent",
  "prompt_injection",
  "deception",
  "exploit_attempt",
  "credential_attack",
  "recon",
  "scan",
  "vuln_exposure",
  "port_deviation",
  "ids",
  "policy",
  "anomaly",
  "other",
];

export const INCIDENT_STATUSES: IncidentStatus[] = [
  "open",
  "investigating",
  "contained",
  "resolved",
  "false_positive",
];

export const ACTOR_TYPES: ActorType[] = ["ai_agent", "automated_scanner", "human", "benign", "unknown"];

export const ACTION_TYPES: ActionType[] = [
  "block_ip",
  "rate_limit",
  "tarpit",
  "deceive",
  "deploy_canary",
  "notify",
  "webhook",
  "nftables_block",
];

/** Action types whose target must be an IP / CIDR (validated again server-side). */
export const IP_TARGET_ACTIONS: ActionType[] = [
  "block_ip",
  "rate_limit",
  "tarpit",
  "deceive",
  "nftables_block",
];

export const ACTION_STATUSES: ActionStatus[] = [
  "proposed",
  "approved",
  "active",
  "expired",
  "reverted",
  "rejected",
  "failed",
];

export const DECEPTION_KINDS: DeceptionKind[] = ["ai_canary", "honeytoken", "decoy_path", "labyrinth"];
