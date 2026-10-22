/**
 * Deception / Mirage (/deception): asset list (kind, path, trips, last trip), create dialog, preview of the
 * served body, trip history, and an explanation of when an AI canary trip is attributed to an AI agent.
 * Active defence happens only on our own assets — fake data, no beacons, no hack-back.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bird, Bot, ChevronDown, ChevronRight, Eye, Plus, RefreshCw, Tags, Trash2, Zap } from "lucide-react";
import { Fragment, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { api } from "@/api/client";
import type { DeceptionAsset, DeceptionKind, Page, TkEvent } from "@/api/types";
import { DECEPTION_KINDS } from "@/api/types-ops";
import { KpiCard, Mono, PageHeader } from "@/components/common";
import { EventDetail } from "@/components/common/EventDetail";
import { FilterChip, Notice, Pager, TableSkeleton } from "@/components/common/OpsKit";
import { deceptionKindLabel, fmt, useCanOperate } from "@/components/common/opsLabels";
import { useOpsLive } from "@/components/common/useOpsLive";
import {
  Badge,
  Button,
  Card,
  Dialog,
  EmptyState,
  ErrorState,
  Table,
  Tabs,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { formatDateTime, formatNumber, timeAgo } from "@/lib/format";
import { useLabel, useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { CreateAssetDialog } from "./CreateAssetDialog";
import { KindTag } from "./kinds";
import { PreviewDialog } from "./PreviewDialog";

type TabKey = "assets" | "trips";
const TRIPS_LIMIT = 50;

const strings = {
  ja: {
    title: "デセプション（Mirage）",
    desc: "正規ユーザーが触れない罠（デコイ・ハニートークン・AI カナリア・迷路）を自組織の資産上に配置し、触れた者を高確度で検知します。",
    create: "資産を作成",
    assets: "資産",
    trips: "トリップ履歴",
    kpiAssets: "有効な資産",
    kpiAssetsHint: "全 {n} 件",
    kpiTrips: "総トリップ数",
    kpiTripsHint: "触れた時点で critical アラート",
    kpiAi: "AI カナリアのトリップ",
    kpiAiHint: "AI エージェント断定の根拠",
    kpiLast: "最終トリップ",
    all: "すべて",
    colKind: "種類",
    colName: "名前",
    colPath: "パス",
    colToken: "カナリア値",
    colTrips: "トリップ",
    colLast: "最終トリップ",
    colEnabled: "有効",
    preview: "プレビュー",
    delete: "削除",
    toggle: "有効/無効を切り替え",
    previewViewer: "プレビューには analyst 以上の権限が必要です",
    emptyAssets: "デセプション資産はまだありません",
    emptyAssetsHint:
      "「資産を作成」から AI カナリアやデコイパスを配置できます。サーバー起動時に既定のデコイもシードされます。",
    noMatch: "この種類の資産はありません",
    emptyTrips: "トリップはまだありません",
    emptyTripsHint: "デコイやトークンに触れたリクエストがここに記録されます。",
    colTime: "時刻",
    colSource: "送信元",
    colAsset: "資産",
    colRequest: "リクエスト",
    colUa: "User-Agent",
    expand: "詳細を表示",
    deleteTitle: "資産を削除",
    deleteBody:
      "「{name}」を削除します。配信が停止し、このカナリア値が使われても検知されなくなります。この操作は取り消せません。",
    cancel: "キャンセル",
    confirmDelete: "削除する",
    retry: "再試行",
    never: "なし",
  },
  en: {
    title: "Deception (Mirage)",
    desc: "Plant traps that legitimate users never touch (decoys, honeytokens, AI canaries, labyrinths) on your own assets and detect whoever touches them with high fidelity.",
    create: "Create asset",
    assets: "Assets",
    trips: "Trip history",
    kpiAssets: "Enabled assets",
    kpiAssetsHint: "{n} total",
    kpiTrips: "Total trips",
    kpiTripsHint: "Each trip raises a critical alert",
    kpiAi: "AI-canary trips",
    kpiAiHint: "Basis for AI-agent attribution",
    kpiLast: "Last trip",
    all: "All",
    colKind: "Kind",
    colName: "Name",
    colPath: "Path",
    colToken: "Canary value",
    colTrips: "Trips",
    colLast: "Last trip",
    colEnabled: "Enabled",
    preview: "Preview",
    delete: "Delete",
    toggle: "Toggle enabled",
    previewViewer: "Preview requires the analyst role",
    emptyAssets: "No deception assets yet",
    emptyAssetsHint:
      "Use “Create asset” to plant AI canaries or decoy paths. Default decoys are also seeded at server start.",
    noMatch: "No assets of this kind",
    emptyTrips: "No trips yet",
    emptyTripsHint: "Requests that touch a decoy or token are recorded here.",
    colTime: "Time",
    colSource: "Source",
    colAsset: "Asset",
    colRequest: "Request",
    colUa: "User-Agent",
    expand: "Show details",
    deleteTitle: "Delete asset",
    deleteBody:
      "Delete “{name}”? It stops being served and use of this canary value will no longer be detected. This cannot be undone.",
    cancel: "Cancel",
    confirmDelete: "Delete",
    retry: "Retry",
    never: "Never",
  },
};

const explainer = {
  ja: {
    title: "AI カナリア — 何が起きたら「AI エージェント」と断定するか",
    what: "デコイページの HTML コメント・不可視要素・robots.txt・OpenAPI の description などに、人間には見えず、文章を読んで行動を決める LLM エージェントだけが従う「隠し指示」を埋め込みます（逆プロンプトインジェクション）。",
    ruleTitle: "判定ルール",
    rule1:
      "カナリア値が隠し指示どおりの形で使われた — 例: 指定ヘッダ（X-Debug-Auth: <token> など）を付けて送信、指示されたパス（/api/internal/<token> など）へアクセス → AI スコア 0.99・カテゴリ「AI エージェント」の critical アラート",
    rule2:
      "カナリア値やデコイパスへの接触はあるが、指示と異なる形（ボディへの貼り付け等）→ デセプションの critical アラート（AI とは断定しない）",
    whyTitle: "なぜ確度が高いか",
    why: "正規ユーザーは不可視の指示を目にしません。従来型スキャナは自然言語の指示を解釈しません。指示に「従う」のは、ページの文章を理解して次の行動を決める LLM エージェントだけです。",
    ethics:
      "倫理: 配信するのは偽データのみ。攻撃者の端末で何かを実行させる仕組み（ビーコン・エクスプロイト）は含まず、反撃も行いません。",
    example:
      "例は説明用です。実際の指示文・ヘッダ名はサーバー設定とテンプレートで決まります（プレビューで確認できます）。",
  },
  en: {
    title: "AI canaries — when a trip is attributed to an AI agent",
    what: "Decoy pages embed a hidden instruction in HTML comments, invisible elements, robots.txt or OpenAPI descriptions. Humans never see it; only an LLM agent that reads the text and decides what to do next will follow it (reverse prompt injection).",
    ruleTitle: "Attribution rules",
    rule1:
      "The canary value is used exactly as instructed — e.g. sent in the specified header (such as X-Debug-Auth: <token>) or by visiting the instructed path (such as /api/internal/<token>) → critical alert with AI score 0.99 and category “AI agent”",
    rule2:
      "A canary value or decoy path is touched in a different form (e.g. pasted into a body) → critical deception alert, without AI attribution",
    whyTitle: "Why this is high-fidelity",
    why: "Legitimate users never see the invisible instruction. Classic scanners do not interpret natural-language instructions. Only an LLM agent that understands the page text and acts on it will comply.",
    ethics:
      "Ethics: only fake data is served. Nothing is executed on the attacker's machine (no beacons, no exploits) and there is no hack-back.",
    example:
      "Examples are illustrative; the actual wording and header names come from server settings and templates (see Preview).",
  },
};

function AiCanaryExplainer() {
  const L = useLocal(explainer);
  return (
    <details open className="group rounded-lg border border-ai/40 bg-ai/5">
      <summary className="flex cursor-pointer select-none items-center gap-2 px-4 py-3 text-sm font-semibold text-ai">
        <ChevronRight className="h-4 w-4 transition-transform group-open:rotate-90" aria-hidden />
        <Bot className="h-4 w-4" aria-hidden />
        {L.title}
      </summary>
      <div className="grid gap-4 border-t border-ai/20 px-4 py-3 text-xs leading-relaxed md:grid-cols-2">
        <div className="space-y-3">
          <p>{L.what}</p>
          <div>
            <div className="mb-1 font-semibold text-muted">{L.whyTitle}</div>
            <p className="text-muted">{L.why}</p>
          </div>
        </div>
        <div className="space-y-2">
          <div className="font-semibold text-muted">{L.ruleTitle}</div>
          <ol className="space-y-2">
            <li className="flex gap-2 rounded-md border border-ai/40 bg-ai/10 p-2">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-ai text-[11px] font-bold text-black">
                1
              </span>
              <span>{L.rule1}</span>
            </li>
            <li className="flex gap-2 rounded-md border border-line bg-surface p-2">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-sev-critical text-[11px] font-bold text-white">
                2
              </span>
              <span>{L.rule2}</span>
            </li>
          </ol>
          <p className="text-[11px] text-muted">{L.example}</p>
          <p className="text-[11px] text-muted">{L.ethics}</p>
        </div>
      </div>
    </details>
  );
}

function maskToken(token: string | null): string {
  if (!token) return "-";
  return token.length <= 10 ? token : `${token.slice(0, 6)}…${token.slice(-4)}`;
}

export function DeceptionPage() {
  const L = useLocal(strings);
  const t = useT();
  const label = useLabel();
  const canOperate = useCanOperate();
  const qc = useQueryClient();
  const [sp, setSp] = useSearchParams();
  const tab: TabKey = sp.get("tab") === "trips" ? "trips" : "assets";
  const setTab = (v: TabKey) =>
    setSp(
      (prev) => {
        const n = new URLSearchParams(prev);
        if (v === "assets") n.delete("tab");
        else n.set("tab", v);
        return n;
      },
      { replace: true },
    );
  const [kindFilter, setKindFilter] = useState<DeceptionKind | "">("");
  const [createOpen, setCreateOpen] = useState(false);
  const [preview, setPreview] = useState<DeceptionAsset | null>(null);
  const [toDelete, setToDelete] = useState<DeceptionAsset | null>(null);
  const [tripsOffset, setTripsOffset] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const assetsQ = useQuery({
    queryKey: ["deception", "assets"],
    queryFn: () => api.get<DeceptionAsset[]>("/deception/assets"),
    refetchInterval: 60_000,
  });
  const tripsQ = useQuery({
    queryKey: ["deception", "trips", tripsOffset],
    queryFn: () => api.get<Page<TkEvent>>("/deception/trips", { limit: TRIPS_LIMIT, offset: tripsOffset }),
    placeholderData: keepPreviousData,
    enabled: tab === "trips",
  });
  useOpsLive(["deception."], [["deception"]]);

  const assets = assetsQ.data ?? [];
  const byId = useMemo(() => new Map(assets.map((a) => [a.id, a])), [assets]);
  const shown = kindFilter ? assets.filter((a) => a.kind === kindFilter) : assets;
  const enabledCount = assets.filter((a) => a.enabled).length;
  const totalTrips = assets.reduce((s, a) => s + (a.trip_count ?? 0), 0);
  const aiTrips = assets.filter((a) => a.kind === "ai_canary").reduce((s, a) => s + (a.trip_count ?? 0), 0);
  const lastTrip = assets
    .map((a) => a.last_tripped)
    .filter((v): v is string => !!v)
    .sort()
    .at(-1);

  const toggle = useMutation({
    mutationFn: (a: DeceptionAsset) =>
      api.patch<DeceptionAsset>(`/deception/assets/${encodeURIComponent(a.id)}`, { enabled: !a.enabled }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["deception", "assets"] }),
  });
  const remove = useMutation({
    mutationFn: (a: DeceptionAsset) => api.delete<unknown>(`/deception/assets/${encodeURIComponent(a.id)}`),
    onSuccess: () => {
      setToDelete(null);
      void qc.invalidateQueries({ queryKey: ["deception", "assets"] });
    },
  });

  const refetch = () => (tab === "assets" ? assetsQ.refetch() : tripsQ.refetch());
  const fetching = tab === "assets" ? assetsQ.isFetching : tripsQ.isFetching;

  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <Bird className="h-5 w-5 text-accent" aria-hidden />
            {L.title}
          </span>
        }
        description={L.desc}
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => void refetch()} disabled={fetching}>
              <RefreshCw className={cn("h-3.5 w-3.5", fetching && "animate-spin")} aria-hidden />
              {t("common.refresh")}
            </Button>
            {canOperate && (
              <Button size="sm" onClick={() => setCreateOpen(true)}>
                <Plus className="h-3.5 w-3.5" aria-hidden />
                {L.create}
              </Button>
            )}
          </>
        }
      />

      <AiCanaryExplainer />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          label={L.kpiAssets}
          value={assetsQ.isLoading ? "…" : enabledCount}
          hint={fmt(L.kpiAssetsHint, { n: assets.length })}
          icon={<Tags className="h-4 w-4" aria-hidden />}
          tone="accent"
        />
        <KpiCard
          label={L.kpiTrips}
          value={assetsQ.isLoading ? "…" : formatNumber(totalTrips)}
          hint={L.kpiTripsHint}
          icon={<Zap className="h-4 w-4" aria-hidden />}
          tone={totalTrips ? "danger" : "neutral"}
        />
        <KpiCard
          label={L.kpiAi}
          value={assetsQ.isLoading ? "…" : formatNumber(aiTrips)}
          hint={L.kpiAiHint}
          icon={<Bot className="h-4 w-4" aria-hidden />}
          tone="ai"
        />
        <KpiCard
          label={L.kpiLast}
          value={<span className="text-base">{lastTrip ? timeAgo(lastTrip) : L.never}</span>}
          hint={lastTrip ? formatDateTime(lastTrip) : undefined}
        />
      </div>

      <div>
        <Tabs<TabKey>
          value={tab}
          onChange={setTab}
          tabs={[
            { value: "assets", label: L.assets },
            { value: "trips", label: L.trips },
          ]}
        />
        <div className="pt-4">
          {tab === "assets" ? (
            <Card>
              <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
                <FilterChip active={kindFilter === ""} onClick={() => setKindFilter("")}>
                  {L.all}
                </FilterChip>
                {DECEPTION_KINDS.map((k) => (
                  <FilterChip
                    key={k}
                    ai={k === "ai_canary"}
                    active={kindFilter === k}
                    onClick={() => setKindFilter(kindFilter === k ? "" : k)}
                  >
                    {label(deceptionKindLabel[k])}
                  </FilterChip>
                ))}
              </div>
              {assetsQ.isLoading ? (
                <TableSkeleton />
              ) : assetsQ.error ? (
                <div className="space-y-2 p-4">
                  <ErrorState error={assetsQ.error} />
                  <Button size="sm" variant="outline" onClick={() => void assetsQ.refetch()}>
                    {L.retry}
                  </Button>
                </div>
              ) : shown.length === 0 ? (
                <EmptyState
                  icon={kindFilter ? undefined : <Bird className="h-8 w-8" aria-hidden />}
                  title={kindFilter ? L.noMatch : L.emptyAssets}
                  hint={kindFilter ? undefined : L.emptyAssetsHint}
                />
              ) : (
                <Table>
                  <THead>
                    <tr>
                      <TH>{L.colKind}</TH>
                      <TH>{L.colName}</TH>
                      <TH>{L.colPath}</TH>
                      <TH>{L.colToken}</TH>
                      <TH className="text-right">{L.colTrips}</TH>
                      <TH>{L.colLast}</TH>
                      <TH>{L.colEnabled}</TH>
                      <TH className="text-right">{t("common.actions")}</TH>
                    </tr>
                  </THead>
                  <TBody>
                    {shown.map((a) => (
                      <TR key={a.id} className={cn(!a.enabled && "opacity-60")}>
                        <TD className="whitespace-nowrap">
                          <KindTag kind={a.kind} />
                        </TD>
                        <TD className="max-w-[260px]">
                          <div className="font-medium">{a.name}</div>
                          {a.description && (
                            <div className="line-clamp-1 text-xs text-muted">{a.description}</div>
                          )}
                        </TD>
                        <TD>
                          <Mono className="break-all">{a.path ?? "-"}</Mono>
                        </TD>
                        <TD>
                          <Mono className="text-muted">{maskToken(a.token)}</Mono>
                        </TD>
                        <TD className="text-right tabular-nums">
                          {a.trip_count > 0 ? (
                            <Badge tone={a.kind === "ai_canary" ? "ai" : "danger"}>{a.trip_count}</Badge>
                          ) : (
                            <span className="text-muted">0</span>
                          )}
                        </TD>
                        <TD
                          className="whitespace-nowrap text-xs text-muted"
                          title={formatDateTime(a.last_tripped)}
                        >
                          {a.last_tripped ? timeAgo(a.last_tripped) : L.never}
                        </TD>
                        <TD>
                          <input
                            type="checkbox"
                            className="accent-[var(--tk-accent)]"
                            aria-label={`${L.toggle}: ${a.name}`}
                            checked={a.enabled}
                            disabled={!canOperate || toggle.isPending}
                            onChange={() => toggle.mutate(a)}
                          />
                        </TD>
                        <TD className="text-right">
                          <div className="flex justify-end gap-1">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => setPreview(a)}
                              disabled={!canOperate}
                              title={canOperate ? L.preview : L.previewViewer}
                            >
                              <Eye className="h-3.5 w-3.5" aria-hidden />
                              {L.preview}
                            </Button>
                            {canOperate && (
                              <Button
                                size="icon"
                                variant="ghost"
                                onClick={() => setToDelete(a)}
                                aria-label={`${L.delete}: ${a.name}`}
                                title={L.delete}
                              >
                                <Trash2 className="h-3.5 w-3.5" aria-hidden />
                              </Button>
                            )}
                          </div>
                        </TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
              )}
              {toggle.error && (
                <div className="p-3">
                  <ErrorState error={toggle.error} />
                </div>
              )}
            </Card>
          ) : (
            <Card>
              {tripsQ.isLoading ? (
                <TableSkeleton />
              ) : tripsQ.error ? (
                <div className="space-y-2 p-4">
                  <ErrorState error={tripsQ.error} />
                  <Button size="sm" variant="outline" onClick={() => void tripsQ.refetch()}>
                    {L.retry}
                  </Button>
                </div>
              ) : !tripsQ.data?.items.length ? (
                <EmptyState
                  icon={<Zap className="h-8 w-8" aria-hidden />}
                  title={L.emptyTrips}
                  hint={L.emptyTripsHint}
                />
              ) : (
                <>
                  <Table>
                    <THead>
                      <tr>
                        <TH className="w-6" />
                        <TH>{L.colTime}</TH>
                        <TH>{L.colSource}</TH>
                        <TH>{L.colAsset}</TH>
                        <TH>{L.colToken}</TH>
                        <TH>{L.colRequest}</TH>
                        <TH>{L.colUa}</TH>
                      </tr>
                    </THead>
                    <TBody>
                      {tripsQ.data.items.map((ev) => {
                        const d = ev.deception ?? {};
                        const assetId = typeof d.asset_id === "string" ? d.asset_id : null;
                        const asset = assetId ? byId.get(assetId) : undefined;
                        const kind = (typeof d.asset_kind === "string" ? d.asset_kind : asset?.kind) ?? "";
                        const token = typeof d.token === "string" ? d.token : null;
                        const open = expanded === ev.id;
                        return (
                          <Fragment key={ev.id}>
                            <TR className={cn(kind === "ai_canary" && "bg-ai/5")}>
                              <TD>
                                <button
                                  type="button"
                                  className="text-muted hover:text-fg"
                                  aria-expanded={open}
                                  aria-label={L.expand}
                                  onClick={() => setExpanded(open ? null : ev.id)}
                                >
                                  {open ? (
                                    <ChevronDown className="h-4 w-4" aria-hidden />
                                  ) : (
                                    <ChevronRight className="h-4 w-4" aria-hidden />
                                  )}
                                </button>
                              </TD>
                              <TD className="whitespace-nowrap text-xs" title={formatDateTime(ev.timestamp)}>
                                {timeAgo(ev.timestamp)}
                              </TD>
                              <TD>
                                <Mono>{ev.source?.ip ?? "-"}</Mono>
                              </TD>
                              <TD>
                                <div className="flex flex-col gap-0.5">
                                  {kind && <KindTag kind={kind} />}
                                  <span className="text-xs text-muted">
                                    {asset?.name ?? assetId?.slice(0, 8) ?? "-"}
                                  </span>
                                </div>
                              </TD>
                              <TD>
                                <Mono className={cn(kind === "ai_canary" ? "text-ai" : "text-muted")}>
                                  {maskToken(token)}
                                </Mono>
                              </TD>
                              <TD className="max-w-[280px]">
                                <Mono className="line-clamp-1 break-all">
                                  {ev.http
                                    ? `${ev.http.method ?? ""} ${ev.http.path ?? ""}`
                                    : (ev.message ?? "-")}
                                </Mono>
                              </TD>
                              <TD className="max-w-[220px]">
                                <span className="line-clamp-1 break-all text-xs text-muted">
                                  {ev.http?.user_agent ?? "-"}
                                </span>
                              </TD>
                            </TR>
                            {open && (
                              <tr>
                                <td colSpan={7} className="bg-surface-2/30 p-3">
                                  <EventDetail event={ev} defaultOpen />
                                </td>
                              </tr>
                            )}
                          </Fragment>
                        );
                      })}
                    </TBody>
                  </Table>
                  <Pager
                    total={tripsQ.data.total}
                    limit={TRIPS_LIMIT}
                    offset={tripsOffset}
                    onChange={setTripsOffset}
                  />
                </>
              )}
            </Card>
          )}
        </div>
      </div>

      {createOpen && (
        <CreateAssetDialog
          open
          onClose={() => setCreateOpen(false)}
          onCreated={(asset) => {
            setCreateOpen(false);
            if (asset.path) setPreview(asset);
          }}
        />
      )}
      <PreviewDialog asset={preview} onClose={() => setPreview(null)} />
      <Dialog
        open={!!toDelete}
        onClose={() => {
          remove.reset();
          setToDelete(null);
        }}
        title={L.deleteTitle}
        footer={
          <>
            <Button
              variant="ghost"
              onClick={() => {
                remove.reset();
                setToDelete(null);
              }}
            >
              {L.cancel}
            </Button>
            <Button
              variant="danger"
              disabled={remove.isPending}
              onClick={() => toDelete && remove.mutate(toDelete)}
            >
              <Trash2 className="h-4 w-4" aria-hidden />
              {L.confirmDelete}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p className="text-sm">{fmt(L.deleteBody, { name: toDelete?.name ?? "" })}</p>
          {toDelete && (
            <Notice>
              <span className="flex flex-wrap gap-3">
                <KindTag kind={toDelete.kind} />
                <Mono>{toDelete.path ?? "-"}</Mono>
              </span>
            </Notice>
          )}
          {remove.error && <ErrorState error={remove.error} />}
        </div>
      </Dialog>
    </div>
  );
}
