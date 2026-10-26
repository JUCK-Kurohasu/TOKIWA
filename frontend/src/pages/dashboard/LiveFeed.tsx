/** Live feed of new alerts / incidents / proposed actions / deception trips pushed over SSE. */
import { Bot, Flag, Gavel, Radar, Siren } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import type { ActorType, Severity } from "@/api/types";
import { AiScore, SeverityDot } from "@/components/common";
import { LiveDot } from "@/components/common/LiveDot";
import { formatClock } from "@/components/common/numfmt";
import { Badge, Card, CardHeader, EmptyState } from "@/components/ui";
import { type LiveMessage, useLiveFeed, useLiveStatus } from "@/hooks/useLiveStream";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const TOPICS = ["alert.", "incident.", "action.proposed", "deception.tripped"] as const;
const AI_CATEGORIES = new Set(["ai_agent", "prompt_injection"]);

interface FeedItem {
  key: string;
  at: number;
  icon: ReactNode;
  kind: string;
  title: string;
  sub?: string;
  severity?: Severity;
  ai: boolean;
  aiScore?: number | null;
  to?: string;
  count?: number;
}

type Loose = Record<string, unknown>;
const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
const num = (v: unknown): number | undefined => (typeof v === "number" ? v : undefined);
const SEVS = new Set(["info", "low", "medium", "high", "critical"]);
const sev = (v: unknown): Severity | undefined =>
  typeof v === "string" && SEVS.has(v) ? (v as Severity) : undefined;

type Labels = Record<
  "alertNew" | "alertUpd" | "incNew" | "incUpd" | "action" | "trip" | "decoy" | "unknown",
  string
>;

function toItem(m: LiveMessage, L: Labels): { id: string; item: FeedItem } | null {
  const d = (m.data && typeof m.data === "object" ? m.data : {}) as Loose;
  const id = str(d.id) ?? `${m.id}`;
  if (m.topic.startsWith("alert.")) {
    const category = str(d.category) ?? "";
    const aiScore = num(d.ai_score) ?? null;
    return {
      id: `alert:${id}`,
      item: {
        key: `${m.id}`,
        at: m.receivedAt,
        icon: <Siren className="h-3.5 w-3.5" />,
        kind: m.topic === "alert.created" ? L.alertNew : L.alertUpd,
        title: str(d.title) ?? L.unknown,
        sub: [str(d.source_ip), category].filter(Boolean).join(" · "),
        severity: sev(d.severity),
        ai: AI_CATEGORIES.has(category) || (aiScore ?? 0) >= 0.7,
        aiScore,
        to: str(d.id) ? `/alerts/${d.id}` : "/alerts",
        count: num(d.count),
      },
    };
  }
  if (m.topic.startsWith("incident.")) {
    const actor = str(d.actor_type) as ActorType | undefined;
    const ips = Array.isArray(d.source_ips)
      ? (d.source_ips as unknown[]).filter((x) => typeof x === "string")
      : [];
    return {
      id: `incident:${id}`,
      item: {
        key: `${m.id}`,
        at: m.receivedAt,
        icon: <Flag className="h-3.5 w-3.5" />,
        kind: m.topic === "incident.created" ? L.incNew : L.incUpd,
        title: str(d.title) ?? L.unknown,
        sub: ips.slice(0, 2).join(", "),
        severity: sev(d.severity),
        ai: actor === "ai_agent",
        aiScore: num(d.ai_score) ?? null,
        to: str(d.id) ? `/incidents/${d.id}` : "/incidents",
      },
    };
  }
  if (m.topic === "action.proposed") {
    return {
      id: `action:${id}`,
      item: {
        key: `${m.id}`,
        at: m.receivedAt,
        icon: <Gavel className="h-3.5 w-3.5" />,
        kind: L.action,
        title: `${str(d.action_type) ?? "?"} → ${str(d.target) ?? "?"}`,
        sub: str(d.reason),
        ai: str(d.proposed_by) === "llm",
        to: "/response",
      },
    };
  }
  if (m.topic === "deception.tripped") {
    return {
      id: `trip:${str(d.event_id) ?? m.id}`,
      item: {
        key: `${m.id}`,
        at: m.receivedAt,
        icon: <Radar className="h-3.5 w-3.5" />,
        kind: L.trip,
        title: `${L.decoy} ${str(d.asset_id)?.slice(0, 8) ?? ""}`,
        sub: str(d.source_ip),
        severity: "high",
        ai: false,
        to: "/deception",
      },
    };
  }
  return null;
}

export function LiveFeed({ className }: { className?: string }) {
  const L = useLocal({
    ja: {
      title: "ライブフィード",
      desc: "新着アラート・インシデント・対処提案",
      waiting: "新着を待機中…",
      waitingHint: "新しいアラートが検知されるとここに流れます",
      alertNew: "新規アラート",
      alertUpd: "アラート更新",
      incNew: "新規インシデント",
      incUpd: "インシデント更新",
      action: "対処提案",
      trip: "デセプション",
      decoy: "デコイ接触",
      unknown: "(無題)",
      ai: "AI",
    },
    en: {
      title: "Live feed",
      desc: "New alerts, incidents and proposed actions",
      waiting: "Waiting for activity…",
      waitingHint: "New alerts appear here as they are detected",
      alertNew: "New alert",
      alertUpd: "Alert updated",
      incNew: "New incident",
      incUpd: "Incident updated",
      action: "Action proposed",
      trip: "Deception",
      decoy: "Decoy tripped",
      unknown: "(untitled)",
      ai: "AI",
    },
  });
  const messages = useLiveFeed(TOPICS, 80);
  const status = useLiveStatus();

  // Newest first; collapse repeated updates of the same alert/incident into the newest entry.
  const seen = new Set<string>();
  const items: FeedItem[] = [];
  for (const m of messages) {
    const r = toItem(m, L);
    if (!r || seen.has(r.id)) continue;
    seen.add(r.id);
    items.push(r.item);
    if (items.length >= 40) break;
  }

  return (
    <Card className={cn("flex min-h-0 flex-col", className)}>
      <CardHeader title={L.title} description={L.desc} actions={<LiveDot status={status} />} />
      <div className="min-h-0 flex-1 overflow-y-auto">
        {items.length === 0 ? (
          <EmptyState title={L.waiting} hint={L.waitingHint} icon={<Bot className="h-6 w-6 opacity-60" />} />
        ) : (
          <ul className="divide-y divide-line" aria-live="polite">
            {items.map((it) => (
              <li key={it.key}>
                <Link
                  to={it.to ?? "#"}
                  className={cn(
                    "flex gap-2.5 border-l-2 px-3 py-2 hover:bg-surface-2/60 focus-visible:outline-2 focus-visible:outline-accent",
                    it.ai ? "border-l-ai bg-ai/[0.04]" : "border-l-transparent",
                  )}
                >
                  <span className={cn("mt-0.5 shrink-0", it.ai ? "text-ai" : "text-muted")}>{it.icon}</span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-1.5 text-[11px] text-muted">
                      <span className="tabular-nums">{formatClock(it.at)}</span>
                      <span>·</span>
                      <span>{it.kind}</span>
                      {it.count != null && it.count > 1 && <span className="tabular-nums">×{it.count}</span>}
                      {it.ai && <Badge tone="ai">{L.ai}</Badge>}
                    </span>
                    <span className="mt-0.5 flex items-center gap-1.5 text-sm">
                      {it.severity && <SeverityDot severity={it.severity} />}
                      <span className="truncate">{it.title}</span>
                    </span>
                    {(it.sub || it.aiScore != null) && (
                      <span className="mt-0.5 flex items-center justify-between gap-2 text-xs text-muted">
                        <span className="truncate font-mono">{it.sub}</span>
                        {it.aiScore != null && <AiScore score={it.aiScore} />}
                      </span>
                    )}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
