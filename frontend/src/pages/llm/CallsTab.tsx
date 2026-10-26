/**
 * LLM call audit log. The list is visible to all users; the detail (redacted request and raw response) is
 * admin-only on the backend. Model text is shown as plain preformatted text, never rendered as HTML/Markdown.
 */
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "@/api/client";
import type { LLMCall, LLMCallDetail, Page } from "@/api/types";
import { LLM_CALL_STATUSES, LLM_PURPOSES } from "@/api/types-intel";
import { OffsetPager } from "@/components/common/OffsetPager";
import { ApiErrorState, LoadingRows, QueryView } from "@/components/common/QueryView";
import { useCan } from "@/components/common/RoleGate";
import { useUrlParams } from "@/components/common/urlState";
import { Badge, Card, Dialog, EmptyState, Select, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { formatDateTime, formatNumber, formatUsd, timeAgo } from "@/lib/format";
import { useLang, useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const LIMIT = 50;

const strings = {
  ja: {
    purpose: "目的",
    status: "状態",
    time: "時刻",
    tier: "ティア",
    model: "モデル",
    tokens: "トークン（入力 / 出力）",
    cost: "費用",
    latency: "応答時間",
    related: "関連",
    empty: "LLM 呼び出しの記録はありません",
    detail: "LLM 呼び出しの詳細",
    adminOnly: "入力・出力の詳細は管理者のみ閲覧できます。",
    provider: "プロバイダ",
    promptVersion: "プロンプト版",
    cache: "キャッシュ（読込 / 書込）",
    webSearch: "Web 検索回数",
    error: "エラー",
    request: "送信内容（マスキング済み）",
    response: "応答",
    none: "（記録なし）",
    redactedNote: "API キー・トークン・メールアドレス等は送信前にマスキングされています。",
  },
  en: {
    purpose: "Purpose",
    status: "Status",
    time: "Time",
    tier: "Tier",
    model: "Model",
    tokens: "Tokens (in / out)",
    cost: "Cost",
    latency: "Latency",
    related: "Related",
    empty: "No LLM calls recorded",
    detail: "LLM call detail",
    adminOnly: "Request/response details are visible to administrators only.",
    provider: "Provider",
    promptVersion: "Prompt version",
    cache: "Cache (read / write)",
    webSearch: "Web searches",
    error: "Error",
    request: "Request (redacted)",
    response: "Response",
    none: "(not recorded)",
    redactedNote: "API keys, tokens, e-mail addresses etc. are masked before sending.",
  },
};

const statusLabels: Record<string, { ja: string; en: string; tone: "accent" | "warn" | "danger" | "ai" }> = {
  ok: { ja: "成功", en: "OK", tone: "accent" },
  refused: { ja: "拒否", en: "Refused", tone: "ai" },
  error: { ja: "エラー", en: "Error", tone: "danger" },
  budget_exceeded: { ja: "予算超過", en: "Over budget", tone: "warn" },
  invalid_output: { ja: "出力不正", en: "Invalid output", tone: "warn" },
};

export function CallStatusBadge({ status }: { status: string }) {
  const { lang } = useLang();
  const s = statusLabels[status];
  return <Badge tone={s?.tone ?? "neutral"}>{s ? s[lang] : status}</Badge>;
}

const RELATED_LINKS: Record<string, string> = {
  alert_id: "/alerts/",
  incident_id: "/incidents/",
  session_id: "/sessions/",
};

function RelatedChips({ related }: { related: Record<string, string> }) {
  const entries = Object.entries(related ?? {});
  if (!entries.length) return <span className="text-xs text-muted">-</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {entries.map(([k, v]) => {
        const base = RELATED_LINKS[k];
        const text = `${k.replace(/_id$/, "")}:${String(v).slice(0, 8)}`;
        const cls = "rounded border border-line px-1 py-0.5 font-mono text-[10px]";
        return base ? (
          <Link
            key={k}
            to={`${base}${encodeURIComponent(v)}`}
            className={cn(cls, "text-muted hover:border-accent hover:text-accent")}
            title={`${k}=${v}`}
            onClick={(e) => e.stopPropagation()}
          >
            {text}
          </Link>
        ) : (
          <span key={k} className={cn(cls, "text-muted")} title={`${k}=${v}`}>
            {text}
          </span>
        );
      })}
    </span>
  );
}

function prettyMaybeJson(text: string): string {
  const t = text.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return text;
  try {
    return JSON.stringify(JSON.parse(t), null, 2);
  } catch {
    return text;
  }
}

function TextBlock({ title, text, note }: { title: string; text: string | null | undefined; note?: string }) {
  const L = useLocal(strings);
  return (
    <section>
      <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">{title}</h4>
      {note && <p className="mb-1 text-[11px] text-muted">{note}</p>}
      <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-bg p-3 font-mono text-[11px] leading-relaxed">
        {text ? prettyMaybeJson(text) : L.none}
      </pre>
    </section>
  );
}

function CallDetailDialog({ id, row, onClose }: { id: string; row?: LLMCall; onClose: () => void }) {
  const L = useLocal(strings);
  const t = useT();
  const can = useCan();
  const q = useQuery({
    queryKey: ["llm", "call", id],
    queryFn: () => api.get<LLMCallDetail>(`/llm/calls/${encodeURIComponent(id)}`),
    enabled: can.admin,
  });
  const c: LLMCall | undefined = q.data ?? row;
  return (
    <Dialog
      open
      wide
      onClose={onClose}
      title={
        <span className="flex flex-wrap items-center gap-2">
          {L.detail}
          {c && <CallStatusBadge status={c.status} />}
          <span className="font-mono text-xs font-normal text-muted">{id}</span>
        </span>
      }
      footer={
        <button type="button" className="text-sm text-muted hover:text-fg" onClick={onClose}>
          {t("common.close")}
        </button>
      }
    >
      <div className="space-y-4">
        {q.isLoading && !c && <LoadingRows rows={5} />}
        {q.error ? <ApiErrorState error={q.error} /> : null}
        {c && (
          <dl className="grid grid-cols-2 gap-3 rounded-md border border-line bg-surface-2/40 p-3 text-sm sm:grid-cols-4">
            {(
              [
                [t("common.time"), formatDateTime(c.created_at)],
                [L.purpose, c.purpose],
                [L.provider, c.provider],
                [
                  L.model,
                  <span key="m" className="font-mono text-xs">
                    {c.model}
                  </span>,
                ],
                [L.tier, c.tier],
                [
                  L.promptVersion,
                  <span key="p" className="font-mono text-xs">
                    {c.prompt_version}
                  </span>,
                ],
                [L.tokens, `${formatNumber(c.input_tokens)} / ${formatNumber(c.output_tokens)}`],
                [L.cache, `${formatNumber(c.cache_read_tokens)} / ${formatNumber(c.cache_write_tokens)}`],
                [L.webSearch, formatNumber(c.web_search_requests)],
                [L.cost, formatUsd(c.cost_usd)],
                [L.latency, `${formatNumber(Math.round(c.latency_ms))} ms`],
                [L.related, <RelatedChips key="r" related={c.related} />],
              ] as const
            ).map(([k, v]) => (
              <div key={String(k)} className="min-w-0">
                <dt className="text-[11px] text-muted">{k}</dt>
                <dd className="mt-0.5 break-words tabular-nums">{v}</dd>
              </div>
            ))}
          </dl>
        )}
        {c?.error && (
          <section>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-sev-critical">
              {L.error}
            </h4>
            <pre className="whitespace-pre-wrap break-words rounded-md border border-sev-critical/30 bg-sev-critical/10 p-3 font-mono text-[11px] text-sev-critical">
              {c.error}
            </pre>
          </section>
        )}
        {can.admin ? (
          q.data && (
            <>
              <TextBlock title={L.request} text={q.data.request_redacted} note={L.redactedNote} />
              <TextBlock title={L.response} text={q.data.response_text} />
            </>
          )
        ) : (
          <p className="rounded-md bg-surface-2 px-3 py-2 text-xs text-muted">{L.adminOnly}</p>
        )}
      </div>
    </Dialog>
  );
}

export function CallsTab() {
  const L = useLocal(strings);
  const t = useT();
  const { lang } = useLang();
  const [params, update] = useUrlParams();
  const purpose = params.get("purpose") ?? "";
  const status = params.get("status") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const callId = params.get("call");

  const query = useQuery({
    queryKey: ["llm", "calls", { purpose, status, offset }],
    queryFn: () => api.get<Page<LLMCall>>("/llm/calls", { purpose, status, limit: LIMIT, offset }),
    placeholderData: keepPreviousData,
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select
          aria-label={L.purpose}
          value={purpose}
          onChange={(e) => update({ purpose: e.target.value, offset: null })}
        >
          <option value="">
            {L.purpose}: {t("common.all")}
          </option>
          {LLM_PURPOSES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </Select>
        <Select
          aria-label={L.status}
          value={status}
          onChange={(e) => update({ status: e.target.value, offset: null })}
        >
          <option value="">
            {L.status}: {t("common.all")}
          </option>
          {LLM_CALL_STATUSES.map((s) => (
            <option key={s} value={s}>
              {statusLabels[s]?.[lang] ?? s}
            </option>
          ))}
        </Select>
      </div>
      <Card>
        <QueryView
          query={query}
          className="p-4"
          rows={8}
          isEmpty={(d) => d.items.length === 0}
          empty={<EmptyState title={L.empty} />}
        >
          {(page) => (
            <>
              <Table>
                <THead>
                  <tr>
                    <TH>{L.time}</TH>
                    <TH>{L.purpose}</TH>
                    <TH>{L.tier}</TH>
                    <TH>{L.model}</TH>
                    <TH>{L.status}</TH>
                    <TH className="text-right">{L.tokens}</TH>
                    <TH className="text-right">{L.cost}</TH>
                    <TH className="text-right">{L.latency}</TH>
                    <TH>{L.related}</TH>
                  </tr>
                </THead>
                <TBody>
                  {page.items.map((c) => (
                    <TR key={c.id} className="cursor-pointer" onClick={() => update({ call: c.id })}>
                      <TD className="whitespace-nowrap text-xs" title={formatDateTime(c.created_at)}>
                        <button
                          type="button"
                          className="hover:text-accent hover:underline"
                          onClick={(e) => {
                            e.stopPropagation();
                            update({ call: c.id });
                          }}
                        >
                          {timeAgo(c.created_at)}
                        </button>
                      </TD>
                      <TD className="text-xs">{c.purpose}</TD>
                      <TD>
                        <Badge tone={c.tier === "deep" ? "ai" : "neutral"}>{c.tier}</Badge>
                      </TD>
                      <TD className="font-mono text-[11px]">{c.model}</TD>
                      <TD>
                        <CallStatusBadge status={c.status} />
                      </TD>
                      <TD className="whitespace-nowrap text-right text-xs tabular-nums">
                        {formatNumber(c.input_tokens)} / {formatNumber(c.output_tokens)}
                        {c.cache_read_tokens > 0 && (
                          <div className="text-[10px] text-muted">
                            cache {formatNumber(c.cache_read_tokens)}
                          </div>
                        )}
                      </TD>
                      <TD className="text-right text-xs tabular-nums">{formatUsd(c.cost_usd)}</TD>
                      <TD className="text-right text-xs tabular-nums">
                        {formatNumber(Math.round(c.latency_ms))} ms
                      </TD>
                      <TD>
                        <RelatedChips related={c.related} />
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <OffsetPager
                total={page.total}
                limit={LIMIT}
                offset={offset}
                onChange={(o) => update({ offset: o || null })}
              />
            </>
          )}
        </QueryView>
      </Card>
      {callId && (
        <CallDetailDialog
          key={callId}
          id={callId}
          row={query.data?.items.find((c) => c.id === callId)}
          onClose={() => update({ call: null })}
        />
      )}
    </div>
  );
}
