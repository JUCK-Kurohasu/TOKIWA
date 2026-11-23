/**
 * Alert suppressions (audit #166 / #173): request bodies and display helpers, kept pure for tests.
 *
 * - Marking an alert false_positive (PATCH /alerts/{id}) suppresses recurrences of the same finding by default
 *   (server `detection.fp_suppress_hours`, 168 h by default; 0 turns it off). The dialog can opt out, set hours,
 *   make it permanent or widen it to every source.
 * - An allowlist (POST /alert-suppressions, admin) declares an authorised scan / load test: a source CIDR and a
 *   duration are mandatory; the server also refuses ranges wider than IPv4 /8 or IPv6 /32 and durations beyond
 *   `detection.allowlist_max_hours` (720 h by default). Those limits are server settings the UI cannot read, so
 *   they are shown as hints and the 422 message is displayed as is.
 */
import type { AlertStatus } from "@/api/types";
import type {
  AlertSuppression,
  AlertSuppressionIn,
  AlertSuppressionMode,
  AlertUpdate,
} from "@/api/types-ops";

export const MAX_SUPPRESS_HOURS = 8760; // schemas.alerts.AlertUpdate.suppress_hours (le=24*365)

/** "default" leaves the choice to the server (suppress for detection.fp_suppress_hours). */
export type FpSuppressChoice = "default" | "none" | "hours" | "permanent";

export interface FpOptions {
  choice: FpSuppressChoice;
  hours: string;
  anySource: boolean;
  reason: string;
}

export const DEFAULT_FP_OPTIONS: FpOptions = { choice: "default", hours: "24", anySource: false, reason: "" };

function parseHours(raw: string, max: number): number | null {
  const s = raw.trim();
  if (!/^\d+(\.\d+)?$/.test(s)) return null;
  const n = Number(s);
  return n > 0 && n <= max ? n : null;
}

/** PATCH body for "mark as false positive", or null when the hours are invalid. */
export function falsePositiveBody(o: FpOptions): AlertUpdate | null {
  const body: AlertUpdate = { status: "false_positive" };
  const reason = o.reason.trim();
  if (reason) body.reason = reason.slice(0, 2000);
  if (o.choice === "none") return { ...body, suppress: false };
  if (o.choice === "hours") {
    const h = parseHours(o.hours, MAX_SUPPRESS_HOURS);
    if (h === null) return null;
    body.suppress_hours = h;
  } else if (o.choice === "permanent") {
    body.suppress_permanent = true;
  }
  if (o.anySource) body.suppress_any_source = true;
  return body;
}

/** Leaving false_positive lifts the suppressions made from this alert (server: lift_for_alert). */
export function liftsSuppression(from: AlertStatus, to: AlertStatus): boolean {
  return from === "false_positive" && to !== "false_positive";
}

export interface AllowlistForm {
  cidr: string;
  hours: string;
  ruleId: string;
  path: string;
  mode: AlertSuppressionMode;
  reason: string;
}

export const EMPTY_ALLOWLIST: AllowlistForm = {
  cidr: "",
  hours: "8",
  ruleId: "",
  path: "",
  mode: "downgrade",
  reason: "",
};

export type AllowlistError = "cidr" | "hours" | null;

const IPV4 = /^(\d{1,3})(\.\d{1,3}){3}$/;

/** Light client-side shape check; the server validates the network and the size limits. */
export function looksLikeCidr(raw: string): boolean {
  const [addr, prefix, ...rest] = raw.trim().split("/");
  if (!addr || rest.length) return false;
  if (prefix !== undefined && !/^\d{1,3}$/.test(prefix)) return false;
  if (IPV4.test(addr)) {
    if (addr.split(".").some((o) => Number(o) > 255)) return false;
    return prefix === undefined || Number(prefix) <= 32;
  }
  if (addr.includes(":") && /^[0-9a-fA-F:.]+$/.test(addr)) {
    return prefix === undefined || Number(prefix) <= 128;
  }
  return false;
}

export function allowlistBody(f: AllowlistForm): { body: AlertSuppressionIn | null; error: AllowlistError } {
  if (!looksLikeCidr(f.cidr)) return { body: null, error: "cidr" };
  const hours = parseHours(f.hours, MAX_SUPPRESS_HOURS);
  if (hours === null) return { body: null, error: "hours" };
  const body: AlertSuppressionIn = {
    kind: "allowlist",
    mode: f.mode,
    source_cidr: f.cidr.trim(),
    hours,
    reason: f.reason.trim().slice(0, 2000),
  };
  if (f.ruleId.trim()) body.rule_id = f.ruleId.trim();
  if (f.path.trim()) body.path = f.path.trim();
  return { body, error: null };
}

export type SuppressionState = "active" | "lifted" | "expired";

export function suppressionState(s: AlertSuppression): SuppressionState {
  if (s.lifted_at) return "lifted";
  return s.active ? "active" : "expired";
}

/** What a false-positive suppression matches, as short labels (signatures / Sigma selections, location, param). */
export function matchSummary(match: Record<string, unknown>): string[] {
  const out: string[] = [];
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String).filter(Boolean) : []);
  const sigs = list(match.signatures);
  if (sigs.length) out.push(sigs.join(", "));
  const sel = list(match.selections);
  if (sel.length) out.push(sel.join(", "));
  const loc = typeof match.location === "string" ? match.location : "";
  const param = typeof match.param === "string" ? match.param : "";
  if (loc || param) out.push(param ? `${loc || "?"}:${param}` : loc);
  return out;
}
