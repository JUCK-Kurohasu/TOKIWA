import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { vulnWithdrawal, WithdrawnBadge, withdrawalOf } from "./IntelBadges";

const AT = "2026-11-20T00:00:00Z";

describe("withdrawn advisories (#132)", () => {
  it("reads the row-level and per-advisory marks", () => {
    expect(vulnWithdrawal(undefined)).toBeNull();
    expect(vulnWithdrawal({ nvd: {} })).toBeNull();
    expect(vulnWithdrawal({ withdrawn_at: AT, withdrawn: { "GHSA-aaaa-bbbb-cccc": AT } })).toEqual({
      kind: "full",
      at: AT,
      advisories: [["GHSA-aaaa-bbbb-cccc", AT]],
    });
    expect(vulnWithdrawal({ withdrawn: { "GHSA-dddd-eeee-ffff": AT } })?.kind).toBe("partial");
    // what GET /intel/matches carries
    expect(withdrawalOf(null, {})).toBeNull();
    expect(withdrawalOf(AT, undefined)?.kind).toBe("full");
    expect(withdrawalOf(undefined, ["not", "a", "map"])).toBeNull();
  });

  it("labels full and partial withdrawals differently", () => {
    const full = renderToStaticMarkup(<WithdrawnBadge withdrawal={withdrawalOf(AT, { "GHSA-x": AT })} />);
    expect(full).toContain("取り下げ済み");
    expect(full).toContain("GHSA-x");
    const partial = renderToStaticMarkup(
      <WithdrawnBadge withdrawal={withdrawalOf(null, { "GHSA-y": AT })} />,
    );
    expect(partial).toContain("一部取り下げ");
    expect(renderToStaticMarkup(<WithdrawnBadge withdrawal={null} />)).toBe("");
  });
});
