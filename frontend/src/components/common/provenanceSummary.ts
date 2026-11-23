/**
 * Who delivered the evidence behind an alert (audit #40). The ingest API stamps every event with server-owned
 * labels (backend `tokiwa.api.routes.ingest`):
 *
 * - `ingest.token_id` / `ingest.token`: the API token that sent it (client-sent `ingest.*` labels are dropped);
 * - `ingest.claimed_sensor_id`: the sensor_id the client claimed when its token is bound to other sensors (the
 *   stored `sensor_id` was forced to the binding);
 * - `ingest.trust = "low"`: gate-only telemetry (`gate.*` / `deception.*`, deception events) from a token without
 *   the `gate` scope - a stolen ingest token can forge those to frame an innocent IP.
 *
 * Events without `ingest.token*` predate the labels or were produced inside TOKIWA (not through the ingest API):
 * they are reported as "no record", never as clean.
 */
import type { TkEvent } from "@/api/types";

export const LABEL_TOKEN_ID = "ingest.token_id";
export const LABEL_TOKEN = "ingest.token";
export const LABEL_TRUST = "ingest.trust";
export const LABEL_CLAIMED_SENSOR = "ingest.claimed_sensor_id";

type ProvenanceEvent = Pick<TkEvent, "id" | "dataset" | "sensor_id" | "labels">;

export interface ProvenanceSource {
  /** null = no provenance label (older data or generated inside TOKIWA). */
  tokenId: string | null;
  tokenName: string | null;
  events: number;
  sensors: string[];
  datasets: string[];
  /** sensor_id values the client claimed but its token binding replaced. */
  claimedSensors: string[];
  lowTrust: number;
}

export interface ProvenanceSummary {
  events: number;
  sources: ProvenanceSource[];
  lowTrust: number;
  claimed: number;
  unlabelled: number;
}

const MAX_LIST = 8;

function push(list: string[], value: string | null | undefined): void {
  if (value && !list.includes(value) && list.length < MAX_LIST) list.push(value);
}

export function summarizeProvenance(events: readonly ProvenanceEvent[]): ProvenanceSummary {
  const byKey = new Map<string, ProvenanceSource>();
  const seen = new Set<string>();
  const out: ProvenanceSummary = { events: 0, sources: [], lowTrust: 0, claimed: 0, unlabelled: 0 };
  for (const e of events) {
    if (seen.has(e.id)) continue; // incidents merge the evidence of several alerts
    seen.add(e.id);
    out.events += 1;
    const labels = e.labels ?? {};
    const tokenId = labels[LABEL_TOKEN_ID] || null;
    const tokenName = labels[LABEL_TOKEN] || null;
    const key = tokenId ?? (tokenName ? `name:${tokenName}` : "");
    let src = byKey.get(key);
    if (!src) {
      src = { tokenId, tokenName, events: 0, sensors: [], datasets: [], claimedSensors: [], lowTrust: 0 };
      byKey.set(key, src);
    }
    src.events += 1;
    push(src.sensors, e.sensor_id);
    push(src.datasets, e.dataset);
    if (!key) out.unlabelled += 1;
    const claimed = labels[LABEL_CLAIMED_SENSOR];
    if (claimed) {
      out.claimed += 1;
      push(src.claimedSensors, claimed);
    }
    if (labels[LABEL_TRUST] === "low") {
      out.lowTrust += 1;
      src.lowTrust += 1;
    }
  }
  // Labelled sources first (most events first), the "no record" group last.
  out.sources = [...byKey.values()].sort(
    (a, b) =>
      Number(a.tokenId === null && a.tokenName === null) -
        Number(b.tokenId === null && b.tokenName === null) || b.events - a.events,
  );
  return out;
}
