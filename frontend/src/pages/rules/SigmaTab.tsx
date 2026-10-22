/** Sigma rules: list (status/source filters), enable/disable, create/edit/validate, delete. */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Search, Trash2 } from "lucide-react";
import { useState } from "react";
import { api } from "@/api/client";
import type { Page, Rule } from "@/api/types";
import { ConfirmDialog } from "@/components/common/DangerConfirm";
import { OffsetPager } from "@/components/common/OffsetPager";
import { ApiErrorState, QueryView } from "@/components/common/QueryView";
import { useCan } from "@/components/common/RoleGate";
import { ToggleSwitch } from "@/components/common/ToggleSwitch";
import { useUrlParams } from "@/components/common/urlState";
import { Button, Card, EmptyState, Input, Select, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { formatNumber, timeAgo } from "@/lib/format";
import { useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { RULE_SOURCES, RULE_STATUSES, RuleSourceBadge, RuleStatusBadge, useRuleLabels } from "./labels";
import { RuleEditorDialog } from "./RuleEditorDialog";

const LIMIT = 100;

const strings = {
  ja: {
    create: "ルールを作成",
    filter: "表示中のルールをタイトルで絞り込み",
    status: "状態",
    source: "出所",
    title: "タイトル",
    hits: "ヒット",
    updated: "更新",
    enabled: "有効",
    empty: "Sigma ルールがありません",
    emptyHint: "「ルールを作成」から追加するか、rules/sigma/ のルールが読み込まれているか確認してください。",
    noMatch: "条件に一致するルールはありません",
    deleteTitle: "ルールを削除",
    deleteBody: "「{name}」を削除します。検知に即時反映され、取り消せません。",
    toggle: "{name} を有効/無効にする",
    edit: "編集",
  },
  en: {
    create: "Create rule",
    filter: "Filter loaded rules by title",
    status: "Status",
    source: "Source",
    title: "Title",
    hits: "Hits",
    updated: "Updated",
    enabled: "On",
    empty: "No Sigma rules",
    emptyHint: "Create one, or check that the rules in rules/sigma/ are loaded.",
    noMatch: "No rules match",
    deleteTitle: "Delete rule",
    deleteBody: 'Delete "{name}". Detection changes immediately; this cannot be undone.',
    toggle: "Enable/disable {name}",
    edit: "Edit",
  },
};

export function SigmaTab() {
  const L = useLocal(strings);
  const t = useT();
  const can = useCan();
  const qc = useQueryClient();
  const labels = useRuleLabels();
  const [params, update] = useUrlParams();
  const status = params.get("status") ?? "";
  const source = params.get("source") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [filter, setFilter] = useState("");
  const [editing, setEditing] = useState<Rule | "new" | null>(null);
  const [toDelete, setToDelete] = useState<Rule | null>(null);

  const query = useQuery({
    queryKey: ["rules", "list", { status, source, offset }],
    queryFn: () => api.get<Page<Rule>>("/rules", { status, source, limit: LIMIT, offset }),
    placeholderData: keepPreviousData,
  });

  const setStatus = useMutation({
    mutationFn: ({ id, next }: { id: string; next: "active" | "disabled" }) =>
      api.patch<Rule>(`/rules/${encodeURIComponent(id)}`, { status: next }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });

  const del = useMutation({
    mutationFn: (r: Rule) => api.delete(`/rules/${encodeURIComponent(r.id)}`),
    onSuccess: () => {
      setToDelete(null);
      qc.invalidateQueries({ queryKey: ["rules"] });
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[14rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" aria-hidden />
          <Input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder={L.filter}
            aria-label={L.filter}
            className="pl-8"
          />
        </div>
        <Select
          aria-label={L.status}
          value={status}
          onChange={(e) => update({ status: e.target.value, offset: null })}
        >
          <option value="">
            {L.status}: {t("common.all")}
          </option>
          {RULE_STATUSES.map((s) => (
            <option key={s} value={s}>
              {labels.status(s)}
            </option>
          ))}
        </Select>
        <Select
          aria-label={L.source}
          value={source}
          onChange={(e) => update({ source: e.target.value, offset: null })}
        >
          <option value="">
            {L.source}: {t("common.all")}
          </option>
          {RULE_SOURCES.map((s) => (
            <option key={s} value={s}>
              {labels.source(s)}
            </option>
          ))}
        </Select>
        {can.analyst && (
          <Button onClick={() => setEditing("new")}>
            <Plus className="h-4 w-4" aria-hidden />
            {L.create}
          </Button>
        )}
      </div>
      {setStatus.error ? <ApiErrorState error={setStatus.error} /> : null}

      <Card>
        <QueryView
          query={query}
          className="p-4"
          rows={8}
          isEmpty={(d) => d.items.length === 0}
          empty={<EmptyState title={L.empty} hint={L.emptyHint} />}
        >
          {(page) => {
            const needle = filter.trim().toLowerCase();
            const rows = needle
              ? page.items.filter((r) => r.title.toLowerCase().includes(needle))
              : page.items;
            return (
              <>
                {rows.length === 0 ? (
                  <EmptyState title={L.noMatch} />
                ) : (
                  <Table>
                    <THead>
                      <tr>
                        <TH className="w-14">{L.enabled}</TH>
                        <TH>{L.title}</TH>
                        <TH>{L.status}</TH>
                        <TH>{L.source}</TH>
                        <TH className="text-right">{L.hits}</TH>
                        <TH>{L.updated}</TH>
                        <TH className="w-20" />
                      </tr>
                    </THead>
                    <TBody>
                      {rows.map((r) => {
                        const togglable = r.status === "active" || r.status === "disabled";
                        return (
                          <TR
                            key={r.id}
                            className={cn("cursor-pointer", r.status === "disabled" && "opacity-60")}
                            onClick={() => setEditing(r)}
                          >
                            <TD>
                              {togglable ? (
                                <ToggleSwitch
                                  checked={r.status === "active"}
                                  disabled={!can.analyst}
                                  busy={setStatus.isPending && setStatus.variables?.id === r.id}
                                  label={L.toggle.replace("{name}", r.title)}
                                  onChange={(on) =>
                                    setStatus.mutate({ id: r.id, next: on ? "active" : "disabled" })
                                  }
                                />
                              ) : (
                                <span className="text-xs text-muted">-</span>
                              )}
                            </TD>
                            <TD>
                              <button
                                type="button"
                                className="text-left text-sm font-medium hover:text-accent hover:underline"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setEditing(r);
                                }}
                              >
                                {r.title}
                              </button>
                              {typeof r.meta?.level === "string" && (
                                <span className="ml-2 text-[11px] uppercase text-muted">{r.meta.level}</span>
                              )}
                            </TD>
                            <TD>
                              <RuleStatusBadge status={r.status} />
                            </TD>
                            <TD>
                              <RuleSourceBadge source={r.source} />
                            </TD>
                            <TD className="text-right tabular-nums text-xs">{formatNumber(r.hit_count)}</TD>
                            <TD className="whitespace-nowrap text-xs text-muted">{timeAgo(r.updated_at)}</TD>
                            <TD>
                              {can.analyst && (
                                <div className="flex justify-end gap-0.5">
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    aria-label={`${L.edit}: ${r.title}`}
                                    title={L.edit}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setEditing(r);
                                    }}
                                  >
                                    <Pencil className="h-3.5 w-3.5" aria-hidden />
                                  </Button>
                                  {r.source !== "builtin" && (
                                    <Button
                                      variant="ghost"
                                      size="icon"
                                      className="hover:text-sev-critical"
                                      aria-label={`${t("common.delete")}: ${r.title}`}
                                      title={t("common.delete")}
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        del.reset();
                                        setToDelete(r);
                                      }}
                                    >
                                      <Trash2 className="h-3.5 w-3.5" aria-hidden />
                                    </Button>
                                  )}
                                </div>
                              )}
                            </TD>
                          </TR>
                        );
                      })}
                    </TBody>
                  </Table>
                )}
                <OffsetPager
                  total={page.total}
                  limit={LIMIT}
                  offset={offset}
                  onChange={(o) => update({ offset: o || null })}
                />
              </>
            );
          }}
        </QueryView>
      </Card>

      {editing && (
        <RuleEditorDialog
          key={editing === "new" ? "new" : editing.id}
          rule={editing === "new" ? null : editing}
          readOnly={!can.analyst}
          onClose={() => setEditing(null)}
        />
      )}
      <ConfirmDialog
        open={!!toDelete}
        title={L.deleteTitle}
        body={L.deleteBody.replace("{name}", toDelete?.title ?? "")}
        confirmLabel={t("common.delete")}
        busy={del.isPending}
        error={del.error}
        onConfirm={() => toDelete && del.mutate(toDelete)}
        onClose={() => setToDelete(null)}
      />
    </div>
  );
}
