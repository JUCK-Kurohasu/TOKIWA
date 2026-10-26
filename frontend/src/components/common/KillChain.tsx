/**
 * Kill-chain display: the 14 MITRE ATT&CK enterprise tactics laid out left-to-right, with the tactics
 * observed in an incident highlighted and numbered in the order they were first seen.
 *
 * Accepts tactic values in the backend's snake_case form ("initial_access"), ATT&CK display names
 * ("Initial Access") or tactic ids ("TA0001"). Unknown values are shown as extra chips at the end.
 */
import type { AttackStage } from "@/api/types";
import { useLabel, useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { attackStageLabel, fmt } from "./opsLabels";

export const ATTACK_TACTICS: Exclude<AttackStage, "none">[] = [
  "reconnaissance",
  "resource_development",
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
];

const TACTIC_IDS: Record<string, AttackStage> = {
  TA0043: "reconnaissance",
  TA0042: "resource_development",
  TA0001: "initial_access",
  TA0002: "execution",
  TA0003: "persistence",
  TA0004: "privilege_escalation",
  TA0005: "defense_evasion",
  TA0006: "credential_access",
  TA0007: "discovery",
  TA0008: "lateral_movement",
  TA0009: "collection",
  TA0011: "command_and_control",
  TA0010: "exfiltration",
  TA0040: "impact",
};

const TACTIC_CODES: Record<string, string> = Object.fromEntries(
  Object.entries(TACTIC_IDS).map(([code, stage]) => [stage, code]),
);

/** Normalize a tactic string to the snake_case AttackStage value (or the cleaned input when unknown). */
export function normalizeTactic(value: string): string {
  const v = value.trim();
  const byId = TACTIC_IDS[v.toUpperCase()];
  if (byId) return byId;
  const snake = v
    .toLowerCase()
    .replace(/&/g, "and")
    .replace(/[\s-]+/g, "_");
  if (snake === "c2" || snake === "command_control") return "command_and_control";
  return snake;
}

function analyse(stages: string[]) {
  const order = new Map<string, number>();
  const unknown: string[] = [];
  for (const raw of stages) {
    const s = normalizeTactic(raw);
    if ((ATTACK_TACTICS as string[]).includes(s)) {
      if (!order.has(s)) order.set(s, order.size + 1);
    } else if (s && s !== "none" && !unknown.includes(raw)) {
      unknown.push(raw);
    }
  }
  // "Furthest" = the right-most observed tactic in ATT&CK order (how deep the intrusion got).
  let furthest: string | null = null;
  for (const t of ATTACK_TACTICS) if (order.has(t)) furthest = t;
  return { order, unknown, furthest };
}

export function KillChain({
  stages,
  current,
  className,
}: {
  stages: string[];
  /** Attack stage from the latest triage verdict (outlined in purple). */
  current?: string | null;
  className?: string;
}) {
  const label = useLabel();
  const L = useLocal({
    ja: {
      observed: "観測 {n} / 14 戦術",
      furthest: "到達段階",
      llm: "LLM 判定の段階",
      none: "戦術はまだ観測されていません",
      other: "その他",
      orderHint: "数字は観測順",
    },
    en: {
      observed: "{n} of 14 tactics observed",
      furthest: "Furthest stage",
      llm: "LLM-assessed stage",
      none: "No tactics observed yet",
      other: "Other",
      orderHint: "Numbers show observation order",
    },
  });
  const { order, unknown, furthest } = analyse(stages);
  const currentNorm = current ? normalizeTactic(current) : null;

  return (
    <div className={cn("space-y-2", className)}>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
        <span className="tabular-nums">{fmt(L.observed, { n: order.size })}</span>
        {furthest && (
          <span>
            {L.furthest}:{" "}
            <span className="font-semibold text-sev-critical">
              {label(attackStageLabel[furthest as AttackStage])}
            </span>
          </span>
        )}
        {currentNorm && currentNorm !== "none" && (
          <span className="inline-flex items-center gap-1">
            <span className="inline-block h-2.5 w-2.5 rounded-sm border-2 border-ai" aria-hidden />
            {L.llm}
          </span>
        )}
        {order.size > 0 && <span>{L.orderHint}</span>}
      </div>

      <ol className="flex gap-1 overflow-x-auto pb-1" aria-label="ATT&CK kill chain">
        {ATTACK_TACTICS.map((t) => {
          const n = order.get(t);
          const isFurthest = t === furthest;
          const isCurrent = t === currentNorm;
          return (
            <li
              key={t}
              className={cn(
                "relative flex min-w-[84px] flex-1 flex-col justify-between gap-1 rounded-md border px-2 py-1.5",
                n
                  ? isFurthest
                    ? "border-sev-critical/60 bg-sev-critical/15"
                    : "border-sev-high/50 bg-sev-high/10"
                  : "border-line bg-surface-2/40 opacity-60",
                isCurrent && "ring-2 ring-ai ring-offset-1 ring-offset-surface",
              )}
              title={`${label(attackStageLabel[t])} (${TACTIC_CODES[t]})`}
              aria-current={isFurthest ? "step" : undefined}
            >
              <div className="flex items-center justify-between gap-1">
                <span className="font-mono text-[9px] text-muted">{TACTIC_CODES[t]}</span>
                {n && (
                  <span
                    className={cn(
                      "flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[10px] font-bold tabular-nums",
                      isFurthest ? "bg-sev-critical text-white" : "bg-sev-high text-black",
                    )}
                  >
                    {n}
                  </span>
                )}
              </div>
              <span className={cn("text-[11px] leading-tight", n ? "font-semibold text-fg" : "text-muted")}>
                {label(attackStageLabel[t])}
              </span>
            </li>
          );
        })}
      </ol>

      {order.size === 0 && <p className="text-xs text-muted">{L.none}</p>}
      {unknown.length > 0 && (
        <div className="flex flex-wrap items-center gap-1 text-xs text-muted">
          {L.other}:
          {unknown.map((u) => (
            <span key={u} className="rounded border border-line px-1.5 py-0.5 font-mono text-[11px]">
              {u}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

/** 14 tiny segments for table rows. */
export function KillChainMini({ stages }: { stages: string[] }) {
  const label = useLabel();
  const { order, furthest } = analyse(stages);
  const names = ATTACK_TACTICS.filter((t) => order.has(t))
    .map((t) => label(attackStageLabel[t]))
    .join(" → ");
  return (
    <span className="inline-flex items-center gap-1.5" title={names || "-"}>
      <span className="inline-flex gap-px" aria-hidden>
        {ATTACK_TACTICS.map((t) => (
          <span
            key={t}
            className={cn(
              "h-3 w-1.5 rounded-[1px]",
              order.has(t) ? (t === furthest ? "bg-sev-critical" : "bg-sev-high") : "bg-surface-2",
            )}
          />
        ))}
      </span>
      <span className="text-[11px] tabular-nums text-muted">{order.size}/14</span>
      <span className="sr-only">{names}</span>
    </span>
  );
}
