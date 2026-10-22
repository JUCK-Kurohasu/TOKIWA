/**
 * Client-side helpers for the "thinking rhythm" view of an actor session.
 *
 * The bands below are UI reference guides only (hypothesis from docs/tasks/detect-ai.md: LLM agents fire
 * short tool-call bursts, then pause for model inference). Attribution itself is computed by the backend
 * (`ActorSession.features` / `ai_score`); nothing here feeds detection. Tune the constants freely.
 */
import type { TkEvent } from "@/api/types";
import type { SessionTimelinePoint } from "@/api/types-core";
import { type StatusClass, statusClass, toEpochMs } from "@/components/common/numfmt";

/** Gaps below this are treated as part of a burst (parallel / scripted requests). */
export const BURST_MAX_MS = 300;
/** Gaps in [THINK_MIN_MS, THINK_MAX_MS] look like "waiting for the model" pauses. */
export const THINK_MIN_MS = 1_500;
export const THINK_MAX_MS = 60_000;

export interface RhythmPoint {
  idx: number;
  t: number;
  /** null for the first request */
  gap: number | null;
  status: number | null;
  path: string | null;
  cls: StatusClass;
}

export function buildPoints(
  timeline: SessionTimelinePoint[] | undefined,
  events: TkEvent[] | undefined,
): RhythmPoint[] {
  const pts: RhythmPoint[] = [];
  if (timeline?.length) {
    const rows = timeline
      .map((p) => ({ ...p, ms: toEpochMs(p.t) }))
      .filter((p): p is typeof p & { ms: number } => p.ms != null)
      .sort((a, b) => a.ms - b.ms);
    rows.forEach((p, i) => {
      const prev = rows[i - 1];
      const gap = p.gap_ms ?? (prev ? p.ms - prev.ms : null);
      pts.push({
        idx: i,
        t: p.ms,
        gap: i === 0 && !p.gap_ms ? null : gap,
        status: p.status,
        path: p.path,
        cls: statusClass(p.status),
      });
    });
    return pts;
  }
  // Fallback: derive from the session's events when the API sends no timeline.
  const evs = (events ?? [])
    .map((e) => ({ e, ms: toEpochMs(e.timestamp) }))
    .filter((x): x is { e: TkEvent; ms: number } => x.ms != null)
    .sort((a, b) => a.ms - b.ms);
  evs.forEach(({ e, ms }, i) => {
    const status = e.http?.status ?? null;
    pts.push({
      idx: i,
      t: ms,
      gap: i === 0 ? null : ms - evs[i - 1].ms,
      status,
      path: e.http?.path ?? e.message ?? null,
      cls: statusClass(status),
    });
  });
  return pts;
}

export interface RhythmStats {
  requests: number;
  medianGap: number | null;
  p90Gap: number | null;
  /** coefficient of variation of gaps (std / mean) */
  cv: number | null;
  burstRatio: number | null;
  thinkRatio: number | null;
  /** both bursts and think pauses are common: the burst -> think -> burst signature */
  bimodal: boolean;
  errorRate: number | null;
}

function quantile(sorted: number[], q: number): number | null {
  if (!sorted.length) return null;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
}

export function rhythmStats(points: RhythmPoint[]): RhythmStats {
  const gaps = points.map((p) => p.gap).filter((g): g is number => g != null && g >= 0);
  const sorted = [...gaps].sort((a, b) => a - b);
  const mean = gaps.length ? gaps.reduce((s, g) => s + g, 0) / gaps.length : null;
  const std =
    mean != null && gaps.length > 1
      ? Math.sqrt(gaps.reduce((s, g) => s + (g - mean) ** 2, 0) / (gaps.length - 1))
      : null;
  const burst = gaps.filter((g) => g <= BURST_MAX_MS).length;
  const think = gaps.filter((g) => g >= THINK_MIN_MS && g <= THINK_MAX_MS).length;
  const withStatus = points.filter((p) => p.status != null);
  const errors = withStatus.filter((p) => (p.status ?? 0) >= 400).length;
  const burstRatio = gaps.length ? burst / gaps.length : null;
  const thinkRatio = gaps.length ? think / gaps.length : null;
  return {
    requests: points.length,
    medianGap: quantile(sorted, 0.5),
    p90Gap: quantile(sorted, 0.9),
    cv: mean && std != null ? std / mean : null,
    burstRatio,
    thinkRatio,
    bimodal: gaps.length >= 6 && (burstRatio ?? 0) >= 0.2 && (thinkRatio ?? 0) >= 0.15,
    errorRate: withStatus.length ? errors / withStatus.length : null,
  };
}

export interface GapBin {
  label: string;
  lo: number;
  hi: number;
  count: number;
  zone: "burst" | "think" | "other";
}

const EDGES = [0, 50, 100, 250, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000, Number.POSITIVE_INFINITY];

function edgeLabel(ms: number): string {
  if (!Number.isFinite(ms)) return "∞";
  return ms < 1000 ? `${ms}` : `${ms / 1000}s`;
}

/** Log-spaced histogram of inter-arrival gaps; bimodality shows up as two humps. */
export function gapHistogram(points: RhythmPoint[]): GapBin[] {
  const bins: GapBin[] = EDGES.slice(0, -1).map((lo, i) => {
    const hi = EDGES[i + 1];
    const label =
      i === 0
        ? `<${hi}ms`
        : !Number.isFinite(hi)
          ? `>${edgeLabel(lo)}`
          : `${edgeLabel(lo)}–${edgeLabel(hi)}${hi < 1000 ? "ms" : ""}`;
    const zone: GapBin["zone"] =
      hi <= BURST_MAX_MS ? "burst" : lo >= THINK_MIN_MS - 500 && hi <= THINK_MAX_MS ? "think" : "other";
    return { label, lo, hi, count: 0, zone };
  });
  for (const p of points) {
    if (p.gap == null) continue;
    const b = bins.find((x) => p.gap != null && p.gap >= x.lo && p.gap < x.hi);
    if (b) b.count += 1;
  }
  return bins;
}

// ---------- indicators ----------

export interface Indicator {
  label: string;
  weight?: number;
  value?: unknown;
  detail?: string;
}

type Loose = Record<string, unknown>;

function pickString(o: Loose, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = o[k];
    if (typeof v === "string" && v) return v;
  }
  return undefined;
}

function pickNumber(o: Loose, keys: string[]): number | undefined {
  for (const k of keys) {
    const v = o[k];
    if (typeof v === "number" && Number.isFinite(v)) return v;
  }
  return undefined;
}

function fromObject(o: Loose, lang: "ja" | "en", fallbackLabel?: string): Indicator {
  const label =
    pickString(o, lang === "ja" ? ["ja", "label_ja", "title_ja"] : ["en", "label_en", "title_en"]) ??
    pickString(o, ["label", "title", "name", "key", "id", "feature", "indicator"]) ??
    fallbackLabel ??
    JSON.stringify(o);
  return {
    label,
    weight: pickNumber(o, ["weight", "contribution", "score", "impact"]),
    value: o.value,
    detail: pickString(o, ["detail", "description", "reason", "evidence"]),
  };
}

/**
 * The indicator format is owned by the detect-ai module and may be a list of strings, a list of
 * objects ({key|label, ja/en, weight|contribution, value, detail}) or a {key: weight|text} map.
 */
export function normalizeIndicators(
  features: Record<string, unknown> | undefined,
  lang: "ja" | "en",
): Indicator[] {
  if (!features) return [];
  const raw = features.indicators ?? features.reasons ?? features.explanations;
  let out: Indicator[] = [];
  if (Array.isArray(raw)) {
    out = raw
      .map((x): Indicator | null => {
        if (typeof x === "string") return { label: x };
        if (x && typeof x === "object") return fromObject(x as Loose, lang);
        return null;
      })
      .filter((x): x is Indicator => x !== null);
  } else if (raw && typeof raw === "object") {
    const o = raw as Loose;
    // {ja: [...], en: [...]} keyed by language
    if (Array.isArray(o[lang])) return normalizeIndicators({ indicators: o[lang] }, lang);
    out = Object.entries(o).map(([k, v]) => {
      if (typeof v === "number") return { label: k, weight: v };
      if (typeof v === "string") return { label: k, detail: v };
      if (v && typeof v === "object") return fromObject(v as Loose, lang, k);
      return { label: k, value: v };
    });
  }
  return out.sort((a, b) => Math.abs(b.weight ?? 0) - Math.abs(a.weight ?? 0));
}

export const INDICATOR_KEYS = new Set(["indicators", "reasons", "explanations"]);
