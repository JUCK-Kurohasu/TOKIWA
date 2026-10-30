/**
 * Response wrappers for the intel / assets / rules / LLM / copilot pages (docs/api-contract.md).
 * Base models (VulnRecord, Advisory, Rule, LLMCall ...) live in ./types.ts; this file only adds the
 * endpoint-specific shapes that the contract describes inline.
 *
 * Fields marked "optional (TODO(verify))" are not pinned down by the contract; the UI tolerates their absence.
 */
import type { Advisory, Asset, Page, Severity, VulnMatch, VulnRecord } from "./types";

// ---------- intel ----------

/** GET /intel/matches returns matches with the asset name joined in. */
export interface VulnMatchWithAsset extends VulnMatch {
  asset_name?: string | null;
}

/** GET /intel/vulns/{id} */
export interface VulnDetailResponse {
  vuln: VulnRecord;
  matches: VulnMatchWithAsset[];
  advisories: Advisory[];
}

export type MatchStatus = VulnMatch["status"];
export const MATCH_STATUSES: MatchStatus[] = ["open", "mitigated", "accepted", "false_positive"];

export type AdvisoryStatus = "new" | "acknowledged" | "done" | "dismissed";
export const ADVISORY_STATUSES: AdvisoryStatus[] = ["new", "acknowledged", "done", "dismissed"];

/** GET /intel/sources (array) */
export interface IntelSourceStatus {
  id: string;
  name: string;
  enabled: boolean;
  last_sync: string | null;
  last_error: string | null;
  records: number | null;
}

// ---------- assets ----------
/** POST /assets, PATCH /assets/{id} body (backend AssetIn). */
export type AssetPayload = Omit<Asset, "id" | "created_at" | "updated_at">;

// ---------- rules ----------

/** POST /rules/validate */
export interface RuleValidation {
  valid: boolean;
  errors: string[];
  title?: string | null;
}

// ---------- LLM ----------
export type LLMProviderName = "auto" | "anthropic" | "openai_compat" | "mock";
export type Effort = "low" | "medium" | "high" | "xhigh" | "max";
export const EFFORTS: Effort[] = ["low", "medium", "high", "xhigh", "max"];

/** GET /llm/config. API keys are never returned. */
export interface LLMConfig {
  provider: LLMProviderName | string;
  /** The provider actually in use ("auto" resolved). "mock" means no real API is called. */
  active_provider?: string;
  available: boolean;
  model_fast: string;
  model_deep: string;
  effort_fast: Effort;
  effort_deep: Effort;
  daily_budget_usd: number;
  spent_today_usd: number;
  output_language: "ja" | "en";
  enable_fallbacks: boolean;
  prompt_cache: boolean;
  /** optional (TODO(verify)): the backend may expose whether a key is stored, never the key itself */
  anthropic_api_key_set?: boolean;
  openai_api_key_set?: boolean;
  openai_base_url?: string | null;
  anthropic_base_url?: string | null;
}

/**
 * PUT /llm/config — partial update. Field names follow backend LLMSettings (config.py).
 * API keys are write-only: send only when the user typed a new value.
 */
export type LLMConfigUpdate = Partial<{
  provider: LLMProviderName;
  model_fast: string;
  model_deep: string;
  effort_fast: Effort;
  effort_deep: Effort;
  daily_budget_usd: number;
  output_language: "ja" | "en";
  enable_fallbacks: boolean;
  prompt_cache: boolean;
  anthropic_api_key: string;
  openai_api_key: string;
  anthropic_base_url: string;
  openai_base_url: string;
}>;

/** by_purpose values: a number (treated as USD cost) or a breakdown object. TODO(verify) with routes/llm.py */
export type PurposeUsage =
  | number
  | { cost_usd?: number; calls?: number; input_tokens?: number; output_tokens?: number };

export interface LLMUsageDay {
  date: string;
  cost_usd: number;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  by_purpose: Record<string, PurposeUsage>;
}

/** GET /llm/usage?days=N */
export interface LLMUsageResponse {
  days: LLMUsageDay[];
}

/** POST /llm/test */
export interface LLMTestResult {
  ok: boolean;
  provider: string;
  model: string;
  latency_ms: number;
  error?: string | null;
}

export const LLM_PURPOSES = [
  "triage",
  "incident",
  "copilot",
  "advisory",
  "research",
  "rule",
  "classify",
  "eval",
  "test",
] as const;

export const LLM_CALL_STATUSES = ["ok", "refused", "error", "budget_exceeded", "invalid_output"] as const;

// ---------- copilot ----------
export interface CopilotConversation {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  /** optional (TODO(verify)): e.g. {"incident_id": "..."} */
  context?: Record<string, unknown> | null;
}

export interface CopilotToolCall {
  id?: string;
  name: string;
  input?: unknown;
  /** optional summary of the tool result when the backend stores it */
  result?: unknown;
  summary?: string | null;
  is_error?: boolean;
}

export interface CopilotMessage {
  id: string;
  role: "user" | "assistant" | "tool" | string;
  content: string;
  created_at: string;
  tool_calls?: CopilotToolCall[] | null;
}

/** GET /copilot/conversations/{id} */
export interface CopilotConversationDetail {
  conversation: CopilotConversation;
  messages: CopilotMessage[];
}

/** SSE payloads from POST /copilot/conversations/{id}/messages */
export type CopilotStreamEvent =
  | { type: "text"; text?: string; content?: string; delta?: string }
  | { type: "tool_call"; id?: string; name?: string; input?: unknown }
  | {
      type: "tool_result";
      id?: string;
      name?: string;
      summary?: string;
      content?: unknown;
      is_error?: boolean;
    }
  | { type: "done"; message_id?: string }
  | { type: "error"; error?: string; message?: string; detail?: string };

// ---------- helpers ----------

/** Some list endpoints return a bare array, others Page<T>; accept both. */
export function asList<T>(data: T[] | Page<T> | null | undefined): T[] {
  if (!data) return [];
  return Array.isArray(data) ? data : (data.items ?? []);
}

export const ASSET_CRITICALITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
