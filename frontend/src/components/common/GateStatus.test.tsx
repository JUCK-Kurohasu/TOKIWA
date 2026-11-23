import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { GateStatus } from "@/api/types";
import { GateStatusNotice, reflectionOf } from "./GateStatus";
import { actionTypeEffect } from "./opsLabels";

const T0 = "2026-11-21T09:00:00Z";

function status(over: Partial<GateStatus> = {}): GateStatus {
  return {
    generated_at: T0,
    current_version: "v1",
    stale_after_seconds: 120,
    gates: [],
    actions: [],
    ...over,
  };
}

const gate = (stale: boolean) => ({
  token_name: "gate-1",
  source_ip: "10.0.0.2",
  first_seen: T0,
  last_seen: T0,
  last_version: "v1",
  last_status: 304,
  fetch_count: 10,
  current: true,
  stale,
});

describe("Gate enforcement state (#145)", () => {
  it("distinguishes no Gate / not applied / applied / applied by stale Gates", () => {
    expect(reflectionOf(undefined, "a")).toEqual({ kind: "unknown" });
    expect(reflectionOf(status(), "a")).toEqual({ kind: "no_gate" });
    const one = status({ gates: [gate(false)] });
    expect(reflectionOf(one, "a")).toEqual({ kind: "pending" });
    const pending = status({
      gates: [gate(false)],
      actions: [
        { action_id: "a", active_since: T0, gates_applied: 0, gates_applied_fresh: 0, last_applied_at: null },
      ],
    });
    expect(reflectionOf(pending, "a").kind).toBe("pending");
    const applied = status({
      gates: [gate(false)],
      actions: [
        { action_id: "a", active_since: T0, gates_applied: 1, gates_applied_fresh: 1, last_applied_at: T0 },
      ],
    });
    expect(reflectionOf(applied, "a")).toEqual({ kind: "applied", gates: 1, at: T0 });
    const stale = status({
      gates: [gate(true)],
      actions: [
        { action_id: "a", active_since: T0, gates_applied: 1, gates_applied_fresh: 0, last_applied_at: T0 },
      ],
    });
    expect(reflectionOf(stale, "a").kind).toBe("applied_stale");
  });

  it("warns on the Response page when no Gate pulls the policy", () => {
    const qc = new QueryClient();
    qc.setQueryData(["gate", "status"], status());
    const out = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <GateStatusNotice />
      </QueryClientProvider>,
    );
    expect(out).toContain("TOKIWA Gate が 1 台もポリシーを取得していません");
  });

  it("describes Gate actions as applying only to traffic through a Gate", () => {
    expect(actionTypeEffect.block_ip.ja).toContain("Gate を経由するリクエストのみ");
    expect(actionTypeEffect.block_ip.en).toContain("Only requests through a TOKIWA Gate");
  });
});
