import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { formatClock, formatTick } from "@/components/common/numfmt";
import { dateTimeTitle, formatDateTime, isoUtc } from "./format";
import { getDisplayTz, storeDisplayTz, zoneName } from "./timezone";

const ISO = "2026-11-11T00:43:09Z";

describe("date/time display zone (#165)", () => {
  beforeAll(() => {
    // Deterministic "browser" zone for the local mode (Node re-reads TZ when it is assigned).
    process.env.TZ = "Asia/Tokyo";
  });
  afterEach(() => storeDisplayTz("local"));

  it("always shows the zone name", () => {
    expect(getDisplayTz()).toBe("local");
    expect(formatDateTime(ISO)).toBe("2026/11/11 9:43:09 JST");
    storeDisplayTz("utc");
    expect(formatDateTime(ISO)).toBe("2026/11/11 0:43:09 UTC");
  });

  it("puts the ISO UTC value in tooltips", () => {
    expect(isoUtc(ISO)).toBe("2026-11-11T00:43:09.000Z");
    expect(dateTimeTitle(ISO)).toBe("2026/11/11 9:43:09 JST\n2026-11-11T00:43:09.000Z");
    expect(dateTimeTitle(null)).toBeUndefined();
    expect(formatDateTime(null)).toBe("-");
    expect(formatDateTime("not a date")).toBe("not a date");
  });

  it("uses a 00-23 hour cycle", () => {
    storeDisplayTz("utc");
    expect(formatDateTime("2026-11-11T00:05:00Z")).toContain(" 0:05:00");
    expect(formatClock("2026-11-11T00:05:00Z")).toBe("0:05:00");
  });

  it("clock and chart ticks follow the display zone", () => {
    expect(formatClock(ISO)).toBe("9:43:09");
    const t = Date.parse("2026-11-10T23:30:00Z");
    expect(formatTick(t, 3600_000)).toBe("08:30");
    expect(formatTick(t, 7 * 86400_000)).toBe("11/11 08:30");
    storeDisplayTz("utc");
    expect(formatTick(t, 7 * 86400_000)).toBe("11/10 23:30");
  });

  it("names the zone for the header toggle", () => {
    expect(zoneName("ja-JP", "local")).toBe("JST");
    expect(zoneName("en-US", "local")).toBe("GMT+9");
    expect(zoneName("ja-JP", "utc")).toBe("UTC");
  });
});
