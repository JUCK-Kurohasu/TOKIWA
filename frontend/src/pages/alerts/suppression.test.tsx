import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import type { AlertSuppression } from "@/api/types-ops";
import { FalsePositiveDialog } from "./FalsePositiveDialog";
import { SuppressionTable } from "./SuppressionTable";
import {
  allowlistBody,
  DEFAULT_FP_OPTIONS,
  EMPTY_ALLOWLIST,
  falsePositiveBody,
  liftsSuppression,
  looksLikeCidr,
  matchSummary,
  suppressionState,
} from "./suppression";

const T0 = "2026-11-23T09:00:00Z";

function supp(over: Partial<AlertSuppression> = {}): AlertSuppression {
  return {
    id: "s1",
    created_at: T0,
    updated_at: T0,
    kind: "false_positive",
    mode: "suppress",
    rule_id: "web.sqli",
    path_key: "/items",
    source_cidr: "203.0.113.10/32",
    match: { signatures: ["sqli.union"], location: "query", param: "id" },
    max_severity: "high",
    reason: "docs search",
    created_by: "alice",
    source_alert_id: "a1",
    expires_at: "2026-11-30T09:00:00Z",
    lifted_at: null,
    lifted_by: null,
    hits: 3,
    last_hit_at: T0,
    active: true,
    ...over,
  };
}

describe("false-positive suppression options (#166)", () => {
  it("leaves the server default alone unless the analyst chooses otherwise", () => {
    expect(falsePositiveBody(DEFAULT_FP_OPTIONS)).toEqual({ status: "false_positive" });
  });

  it("maps every choice to the PATCH fields", () => {
    const base = { ...DEFAULT_FP_OPTIONS, reason: "  internal docs  " };
    expect(falsePositiveBody({ ...base, choice: "none", anySource: true })).toEqual({
      status: "false_positive",
      reason: "internal docs",
      suppress: false, // opting out never widens to any source
    });
    expect(falsePositiveBody({ ...base, choice: "hours", hours: "48" })).toMatchObject({
      suppress_hours: 48,
    });
    expect(falsePositiveBody({ ...base, choice: "permanent", anySource: true })).toMatchObject({
      suppress_permanent: true,
      suppress_any_source: true,
    });
  });

  it("rejects hours the API would refuse", () => {
    for (const hours of ["0", "-1", "abc", "", "8761"]) {
      expect(falsePositiveBody({ ...DEFAULT_FP_OPTIONS, choice: "hours", hours })).toBeNull();
    }
    expect(falsePositiveBody({ ...DEFAULT_FP_OPTIONS, choice: "hours", hours: "8760" })).not.toBeNull();
  });

  it("warns only when leaving false_positive", () => {
    expect(liftsSuppression("false_positive", "acknowledged")).toBe(true);
    expect(liftsSuppression("false_positive", "false_positive")).toBe(false);
    expect(liftsSuppression("new", "resolved")).toBe(false);
  });

  it("renders the dialog with the server default selected", () => {
    const out = renderToStaticMarkup(<FalsePositiveDialog open onCancel={() => {}} onConfirm={() => {}} />);
    expect(out).toContain("誤検知にする");
    expect(out).toContain("detection.fp_suppress_hours");
    expect(out).toMatch(/<option value="default" selected="">/);
  });
});

describe("allowlist form (#173)", () => {
  it("requires a CIDR and a duration", () => {
    expect(allowlistBody(EMPTY_ALLOWLIST).error).toBe("cidr");
    expect(allowlistBody({ ...EMPTY_ALLOWLIST, cidr: "10.20.0.70/32", hours: "" }).error).toBe("hours");
    expect(allowlistBody({ ...EMPTY_ALLOWLIST, cidr: "10.20.0.70/32", hours: "0" }).error).toBe("hours");
    const { body, error } = allowlistBody({
      ...EMPTY_ALLOWLIST,
      cidr: " 10.20.0.0/24 ",
      hours: "8",
      ruleId: " web.request_flood ",
      path: "",
      reason: "pentest",
    });
    expect(error).toBeNull();
    expect(body).toEqual({
      kind: "allowlist",
      mode: "downgrade",
      source_cidr: "10.20.0.0/24",
      hours: 8,
      rule_id: "web.request_flood",
      reason: "pentest",
    });
  });

  it("checks the CIDR shape (the server checks the size limits)", () => {
    for (const ok of ["10.0.0.1", "10.0.0.0/8", "2001:db8::/32", "2001:db8::1"])
      expect(looksLikeCidr(ok)).toBe(true);
    for (const bad of [
      "",
      "10.0.0",
      "10.0.0.256/24",
      "10.0.0.0/33",
      "host.example",
      "10.0.0.0/8/1",
      "::/129",
    ]) {
      expect(looksLikeCidr(bad)).toBe(false);
    }
  });
});

describe("suppression list", () => {
  it("derives the state and the match summary", () => {
    expect(suppressionState(supp())).toBe("active");
    expect(suppressionState(supp({ active: false }))).toBe("expired");
    expect(suppressionState(supp({ active: false, lifted_at: T0, lifted_by: "bob" }))).toBe("lifted");
    expect(matchSummary(supp().match)).toEqual(["sqli.union", "query:id"]);
    expect(matchSummary({ selections: ["sel_a", "sel_b"] })).toEqual(["sel_a, sel_b"]);
    expect(matchSummary({})).toEqual([]);
  });

  it("renders allowlists and false positives with their scope", () => {
    const out = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <SuppressionTable
            items={[
              supp(),
              supp({
                id: "s2",
                kind: "allowlist",
                mode: "downgrade",
                rule_id: null,
                path_key: null,
                source_cidr: "10.20.0.0/24",
                match: {},
                max_severity: null,
                source_alert_id: null,
              }),
            ]}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(out).toContain("誤検知");
    expect(out).toContain("許可リスト");
    expect(out).toContain("10.20.0.0/24");
    expect(out).toContain("全ルール");
    expect(out).toContain("info で記録");
    expect(out).toContain("sqli.union");
  });
});
