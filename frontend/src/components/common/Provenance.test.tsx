import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { AlertDetail, ResponseAction, TkEvent } from "@/api/types";
import { ActionProvenance, ProvenancePanel } from "./Provenance";
import { summarizeProvenance } from "./provenanceSummary";

let n = 0;
function ev(labels: Record<string, string> = {}, over: Partial<TkEvent> = {}): TkEvent {
  n += 1;
  return {
    id: `e${n}`,
    timestamp: "2026-11-23T09:00:00Z",
    kind: "http",
    dataset: "gate.http",
    sensor_id: "gate-prod-1",
    labels,
    ...over,
  } as TkEvent;
}

const GATE = { "ingest.token_id": "tok-gate-0001", "ingest.token": "gate-prod" };
const SIM = { "ingest.token_id": "tok-sim-0002", "ingest.token": "lab-sim" };

describe("evidence provenance (#40)", () => {
  it("groups by token and counts low-trust and claimed events", () => {
    const sum = summarizeProvenance([
      ev(GATE),
      ev(GATE),
      ev({ ...SIM, "ingest.trust": "low" }, { sensor_id: "token:lab-sim" }),
      ev(
        { ...SIM, "ingest.claimed_sensor_id": "gate-prod-1" },
        { sensor_id: "web-1", dataset: "nginx.access" },
      ),
      ev({}, { sensor_id: null }),
    ]);
    expect(sum.events).toBe(5);
    expect(sum.lowTrust).toBe(1);
    expect(sum.claimed).toBe(1);
    expect(sum.unlabelled).toBe(1);
    expect(sum.sources.map((s) => [s.tokenName, s.events])).toEqual([
      ["gate-prod", 2],
      ["lab-sim", 2],
      [null, 1], // "no record" is listed last, never folded into a token
    ]);
    const sim = sum.sources[1];
    expect(sim.sensors).toEqual(["token:lab-sim", "web-1"]);
    expect(sim.claimedSensors).toEqual(["gate-prod-1"]);
    expect(sim.datasets).toEqual(["gate.http", "nginx.access"]);
  });

  it("counts an event once when incidents merge the evidence of several alerts", () => {
    const shared = ev(GATE);
    expect(summarizeProvenance([shared, shared, ev(GATE)]).events).toBe(2);
  });

  it("warns before approval when gate telemetry came from a non-gate token", () => {
    const out = renderToStaticMarkup(
      <ProvenancePanel events={[ev({ ...SIM, "ingest.trust": "low" }), ev(GATE)]} total={250} />,
    );
    expect(out).toContain("gate スコープの無いトークン");
    expect(out).toContain("lab-sim");
    expect(out).toContain("低信頼 1 件");
    expect(out).toContain("証拠イベント 250 件のうち最新 2 件から集計");
    const clean = renderToStaticMarkup(<ProvenancePanel events={[ev(GATE)]} />);
    expect(clean).not.toContain("gate スコープの無いトークン");
    const unlabelled = renderToStaticMarkup(<ProvenancePanel events={[ev({})]} />);
    expect(unlabelled).toContain("出所の記録なし");
  });

  it("shows the alert's provenance in the approval dialog", () => {
    const qc = new QueryClient();
    const alert = { id: "a1", evidence: [ev({ ...SIM, "ingest.trust": "low" })], evidence_event_ids: ["x"] };
    qc.setQueryData(["alerts", "detail", "a1"], alert as unknown as AlertDetail);
    const action = { id: "act1", alert_id: "a1", incident_id: null } as unknown as ResponseAction;
    const out = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <ActionProvenance action={action} />
      </QueryClientProvider>,
    );
    expect(out).toContain("証拠を送ったトークン / センサー");
    expect(out).toContain("lab-sim");
    expect(out).toContain("gate スコープの無いトークン");
    const manual = { id: "act2", alert_id: null, incident_id: null } as unknown as ResponseAction;
    expect(
      renderToStaticMarkup(
        <QueryClientProvider client={qc}>
          <ActionProvenance action={manual} />
        </QueryClientProvider>,
      ),
    ).toBe("");
  });
});
