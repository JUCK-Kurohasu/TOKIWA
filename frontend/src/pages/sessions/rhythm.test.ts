import { describe, expect, it } from "vitest";
import type { SessionTimelinePoint } from "@/api/types-core";
import { buildPoints, gapHistogram, normalizeIndicators, rhythmStats } from "./rhythm";

const T0 = Date.parse("2026-10-22T00:00:00Z");

/** Agent-like: bursts of 3 requests ~40ms apart, then 4-8s "thinking" pauses. */
function agentTimeline(cycles: number): SessionTimelinePoint[] {
  const out: SessionTimelinePoint[] = [];
  let t = T0;
  for (let c = 0; c < cycles; c++) {
    for (let i = 0; i < 3; i++) {
      const gap = out.length === 0 ? null : i === 0 ? 4000 + c * 500 : 40;
      t += gap ?? 0;
      out.push({
        t: new Date(t).toISOString(),
        path: `/api/v1/item/${c}`,
        status: i === 2 ? 500 : 200,
        gap_ms: gap,
      });
    }
  }
  return out;
}

describe("buildPoints", () => {
  it("sorts by time, keeps gaps and classifies status", () => {
    const pts = buildPoints(
      [
        { t: "2026-10-22T00:00:02Z", path: "/b", status: 404, gap_ms: 2000 },
        { t: "2026-10-22T00:00:00Z", path: "/a", status: 200, gap_ms: null },
      ],
      [],
    );
    expect(pts.map((p) => p.path)).toEqual(["/a", "/b"]);
    expect(pts[0].gap).toBeNull();
    expect(pts[1].gap).toBe(2000);
    expect(pts[1].cls).toBe("client");
  });

  it("accepts epoch seconds and derives missing gaps", () => {
    const pts = buildPoints(
      [
        { t: 1_700_000_000, path: "/a", status: 200, gap_ms: null },
        { t: 1_700_000_001.5, path: "/b", status: 200, gap_ms: null },
      ],
      [],
    );
    expect(pts[1].gap).toBe(1500);
  });

  it("falls back to events when the timeline is empty", () => {
    const pts = buildPoints(
      [],
      [
        {
          id: "1",
          timestamp: "2026-10-22T00:00:00.000Z",
          kind: "http",
          dataset: "gate.http",
          http: { status: 200 },
        },
        {
          id: "2",
          timestamp: "2026-10-22T00:00:00.250Z",
          kind: "http",
          dataset: "gate.http",
          http: { status: 503 },
        },
      ],
    );
    expect(pts).toHaveLength(2);
    expect(pts[1].gap).toBe(250);
    expect(pts[1].cls).toBe("server");
  });
});

describe("rhythmStats / gapHistogram", () => {
  it("detects the burst -> think bimodal signature", () => {
    const pts = buildPoints(agentTimeline(6), []);
    const s = rhythmStats(pts);
    expect(s.requests).toBe(18);
    expect(s.bimodal).toBe(true);
    expect(s.burstRatio).toBeGreaterThan(0.5);
    expect(s.thinkRatio).toBeGreaterThan(0.2);
    expect(s.errorRate).toBeCloseTo(6 / 18);
    const hist = gapHistogram(pts);
    expect(hist.find((b) => b.label === "<50ms")?.count).toBe(12);
    expect(hist.filter((b) => b.zone === "think").reduce((n, b) => n + b.count, 0)).toBe(5);
  });

  it("does not flag a steady scanner as bimodal", () => {
    const tl: SessionTimelinePoint[] = Array.from({ length: 30 }, (_, i) => ({
      t: T0 + i * 100,
      path: `/w/${i}`,
      status: 404,
      gap_ms: i === 0 ? null : 100,
    }));
    const s = rhythmStats(buildPoints(tl, []));
    expect(s.bimodal).toBe(false);
    expect(s.cv).toBeCloseTo(0);
  });
});

describe("normalizeIndicators", () => {
  it("handles string lists", () => {
    expect(normalizeIndicators({ indicators: ["a", "b"] }, "ja").map((i) => i.label)).toEqual(["a", "b"]);
  });

  it("handles objects with localized labels and sorts by weight", () => {
    const out = normalizeIndicators(
      {
        indicators: [
          { key: "ua", ja: "AI系UA", en: "AI UA", weight: 0.1 },
          { key: "rhythm", ja: "思考待ちリズム", en: "Think rhythm", weight: 0.9, value: 0.42 },
        ],
      },
      "en",
    );
    expect(out[0]).toMatchObject({ label: "Think rhythm", weight: 0.9, value: 0.42 });
    expect(out[1].label).toBe("AI UA");
  });

  it("handles maps and language-keyed lists", () => {
    expect(normalizeIndicators({ indicators: { burst: 0.3, ua: "python-httpx" } }, "ja")).toEqual([
      { label: "burst", weight: 0.3 },
      { label: "ua", detail: "python-httpx" },
    ]);
    expect(normalizeIndicators({ indicators: { ja: ["日本語"], en: ["english"] } }, "ja")[0].label).toBe(
      "日本語",
    );
  });

  it("returns [] without indicators", () => {
    expect(normalizeIndicators({ cv: 1 }, "ja")).toEqual([]);
    expect(normalizeIndicators(undefined, "ja")).toEqual([]);
  });
});
