/** Built-in detectors with runtime enable/disable (persisted server-side in detection.overrides). */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "@/api/client";
import type { DetectorInfo, Page } from "@/api/types";
import { asList } from "@/api/types-intel";
import { MitreLinks } from "@/components/common/IntelBadges";
import { ApiErrorState, QueryView } from "@/components/common/QueryView";
import { useCan } from "@/components/common/RoleGate";
import { ToggleSwitch } from "@/components/common/ToggleSwitch";
import { Badge, Card, EmptyState, Input, Select, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const strings = {
  ja: {
    search: "検知器名・説明で検索",
    category: "カテゴリ",
    enabled: "有効",
    detector: "検知器",
    description: "説明",
    kinds: "対象イベント",
    mitre: "MITRE ATT&CK",
    summary: "{on} / {total} 件が有効",
    empty: "検知器がありません",
    noMatch: "条件に一致する検知器はありません",
    toggle: "{name} を有効/無効にする",
  },
  en: {
    search: "Search detector name or description",
    category: "Category",
    enabled: "On",
    detector: "Detector",
    description: "Description",
    kinds: "Event kinds",
    mitre: "MITRE ATT&CK",
    summary: "{on} of {total} enabled",
    empty: "No detectors",
    noMatch: "No detectors match",
    toggle: "Enable/disable {name}",
  },
};

const AI_CATEGORIES = /ai|llm|prompt|deception|canary/i;
const KEY = ["rules", "detectors"];

export function DetectorsTab() {
  const L = useLocal(strings);
  const t = useT();
  const can = useCan();
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [category, setCategory] = useState("");

  const query = useQuery({
    queryKey: KEY,
    queryFn: () => api.get<DetectorInfo[] | Page<DetectorInfo>>("/detectors"),
    select: asList,
  });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch<DetectorInfo>(`/detectors/${encodeURIComponent(id)}`, { enabled }),
    onMutate: async ({ id, enabled }) => {
      await qc.cancelQueries({ queryKey: KEY });
      const prev = qc.getQueryData(KEY);
      qc.setQueryData(KEY, (old: DetectorInfo[] | Page<DetectorInfo> | undefined) => {
        const patchOne = (d: DetectorInfo) => (d.id === id ? { ...d, enabled } : d);
        if (!old) return old;
        return Array.isArray(old) ? old.map(patchOne) : { ...old, items: old.items.map(patchOne) };
      });
      return { prev };
    },
    onError: (_e, _v, ctx) => {
      if (ctx?.prev !== undefined) qc.setQueryData(KEY, ctx.prev);
    },
    onSettled: () => qc.invalidateQueries({ queryKey: KEY }),
  });

  const categories = useMemo(
    () => [...new Set((query.data ?? []).map((d) => d.category))].sort(),
    [query.data],
  );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[16rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" aria-hidden />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={L.search}
            aria-label={L.search}
            className="pl-8"
          />
        </div>
        <Select aria-label={L.category} value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">
            {L.category}: {t("common.all")}
          </option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </Select>
        {query.data && (
          <span className="text-xs text-muted">
            {L.summary
              .replace("{on}", String(query.data.filter((d) => d.enabled).length))
              .replace("{total}", String(query.data.length))}
          </span>
        )}
      </div>
      {toggle.error ? <ApiErrorState error={toggle.error} /> : null}
      <Card>
        <QueryView
          query={query}
          className="p-4"
          rows={8}
          isEmpty={(d) => d.length === 0}
          empty={<EmptyState title={L.empty} />}
        >
          {(detectors) => {
            const needle = q.trim().toLowerCase();
            const rows = detectors
              .filter((d) => !category || d.category === category)
              .filter(
                (d) =>
                  !needle ||
                  d.name.toLowerCase().includes(needle) ||
                  d.id.toLowerCase().includes(needle) ||
                  d.description.toLowerCase().includes(needle),
              )
              .sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
            if (!rows.length) return <EmptyState title={L.noMatch} />;
            return (
              <Table>
                <THead>
                  <tr>
                    <TH className="w-14">{L.enabled}</TH>
                    <TH>{L.detector}</TH>
                    <TH>{L.description}</TH>
                    <TH>{L.category}</TH>
                    <TH>{L.kinds}</TH>
                    <TH>{L.mitre}</TH>
                  </tr>
                </THead>
                <TBody>
                  {rows.map((d) => (
                    <TR key={d.id} className={cn(!d.enabled && "opacity-60")}>
                      <TD>
                        <ToggleSwitch
                          checked={d.enabled}
                          disabled={!can.analyst}
                          busy={toggle.isPending && toggle.variables?.id === d.id}
                          label={L.toggle.replace("{name}", d.name)}
                          onChange={(enabled) => toggle.mutate({ id: d.id, enabled })}
                        />
                      </TD>
                      <TD>
                        <div className="text-sm font-medium">{d.name}</div>
                        <div className="font-mono text-[11px] text-muted">{d.id}</div>
                      </TD>
                      <TD className="max-w-md text-xs text-muted">{d.description}</TD>
                      <TD>
                        <Badge tone={AI_CATEGORIES.test(d.category) ? "ai" : "neutral"}>{d.category}</Badge>
                      </TD>
                      <TD>
                        <div className="flex flex-wrap gap-1">
                          {d.kinds.map((k) => (
                            <span key={k} className="font-mono text-[10px] text-muted">
                              {k}
                            </span>
                          ))}
                        </div>
                      </TD>
                      <TD>
                        <MitreLinks ids={d.mitre} />
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            );
          }}
        </QueryView>
      </Card>
    </div>
  );
}
