/** Port baselines (allowed listeners): list, filter by host, add, delete. */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ListChecks, Plus, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "@/api/client";
import type { PortBaseline } from "@/api/types-core";
import { Mono } from "@/components/common";
import { ConfirmButton } from "@/components/common/ConfirmButton";
import { DataState } from "@/components/common/DataState";
import { Badge, Button, Card, CardHeader, Select, Table, TBody, TD, TH, THead, TR } from "@/components/ui";
import { useApiQuery } from "@/hooks/useApi";
import { formatDateTime } from "@/lib/format";
import { useLocal } from "@/lib/i18n";

export function BaselinesPanel({
  canWrite,
  knownHosts,
  onAdd,
  flash,
}: {
  canWrite: boolean;
  knownHosts: string[];
  onAdd: () => void;
  flash: (msg: string, tone?: "success" | "danger") => void;
}) {
  const L = useLocal({
    ja: {
      title: "ポートベースライン",
      desc: "許可された listener。ここに無い待ち受けは逸脱として検知されます（FR-02）",
      add: "追加",
      host: "ホスト",
      all: "すべて",
      allHosts: "全ホスト",
      proto: "プロトコル",
      port: "ポート",
      process: "プロセス",
      anyProcess: "任意",
      exposure: "公開",
      publicOk: "全IF可",
      localOnly: "限定",
      note: "メモ",
      created: "作成",
      delete: "削除",
      deleted: "ベースラインを削除しました",
      empty: "ベースラインはまだありません",
      emptyHint: "「ポート」タブの「現状を学習」で一括登録できます",
      readonly: "閲覧のみ（変更には analyst 以上のロールが必要）",
    },
    en: {
      title: "Port baselines",
      desc: "Allowed listeners. Anything else listening is flagged as a deviation (FR-02)",
      add: "Add",
      host: "Host",
      all: "All",
      allHosts: "All hosts",
      proto: "Proto",
      port: "Port",
      process: "Process",
      anyProcess: "any",
      exposure: "Exposure",
      publicOk: "all IFs ok",
      localOnly: "restricted",
      note: "Note",
      created: "Created",
      delete: "Delete",
      deleted: "Baseline deleted",
      empty: "No baselines yet",
      emptyHint: "Use “Learn current state” on the Ports tab to bootstrap",
      readonly: "Read-only (analyst role required to change)",
    },
  });
  const qc = useQueryClient();
  const [hostFilter, setHostFilter] = useState("");
  const q = useApiQuery<PortBaseline[]>(["hosts", "baselines"], "/hosts/baselines");

  const hostOptions = useMemo(() => {
    const s = new Set<string>(knownHosts);
    for (const b of q.data ?? []) s.add(b.host);
    s.delete("*");
    return [...s].sort();
  }, [knownHosts, q.data]);

  const rows = useMemo(
    () =>
      [...(q.data ?? [])]
        .filter((b) => !hostFilter || b.host === hostFilter)
        .sort((a, b) => a.host.localeCompare(b.host) || a.port - b.port),
    [q.data, hostFilter],
  );

  const del = useMutation({
    mutationFn: (id: string) => api.delete<unknown>(`/hosts/baselines/${id}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["hosts"] });
      flash(L.deleted);
    },
    onError: (e) => flash(e instanceof Error ? e.message : String(e), "danger"),
  });

  return (
    <Card>
      <CardHeader
        title={L.title}
        description={canWrite ? L.desc : `${L.desc} — ${L.readonly}`}
        actions={
          <>
            <Select
              value={hostFilter}
              onChange={(e) => setHostFilter(e.target.value)}
              className="h-7 text-xs"
              aria-label={L.host}
            >
              <option value="">
                {L.host}: {L.all}
              </option>
              <option value="*">{L.allHosts} (*)</option>
              {hostOptions.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </Select>
            {canWrite && (
              <Button size="sm" onClick={onAdd}>
                <Plus className="h-3.5 w-3.5" />
                {L.add}
              </Button>
            )}
          </>
        }
      />
      <DataState
        loading={q.isLoading}
        error={q.error}
        empty={!!q.data && rows.length === 0}
        emptyTitle={L.empty}
        emptyHint={L.emptyHint}
        emptyIcon={<ListChecks className="h-6 w-6 opacity-60" />}
        onRetry={() => q.refetch()}
        className="p-4"
      >
        <Table>
          <THead>
            <tr>
              <TH>{L.host}</TH>
              <TH>{L.proto}</TH>
              <TH className="text-right">{L.port}</TH>
              <TH>{L.process}</TH>
              <TH>{L.exposure}</TH>
              <TH className="hidden md:table-cell">{L.note}</TH>
              <TH className="hidden lg:table-cell">{L.created}</TH>
              {canWrite && <TH className="w-[150px]" />}
            </tr>
          </THead>
          <TBody>
            {rows.map((b) => (
              <TR key={b.id}>
                <TD>
                  {b.host === "*" ? <Badge>{L.allHosts}</Badge> : <span className="text-sm">{b.host}</span>}
                </TD>
                <TD className="font-mono text-xs">{b.protocol}</TD>
                <TD className="text-right font-mono text-xs font-semibold tabular-nums">{b.port}</TD>
                <TD className="text-xs">
                  {b.process_name ? (
                    <Mono>{b.process_name}</Mono>
                  ) : (
                    <span className="text-muted">{L.anyProcess}</span>
                  )}
                </TD>
                <TD>
                  {b.allow_public ? <Badge tone="warn">{L.publicOk}</Badge> : <Badge>{L.localOnly}</Badge>}
                </TD>
                <TD
                  className="hidden max-w-[260px] truncate text-xs text-muted md:table-cell"
                  title={b.note ?? undefined}
                >
                  {b.note ?? "-"}
                </TD>
                <TD className="hidden whitespace-nowrap text-xs text-muted lg:table-cell">
                  {formatDateTime(b.created_at)}
                </TD>
                {canWrite && (
                  <TD className="text-right">
                    <ConfirmButton
                      onConfirm={() => del.mutate(b.id)}
                      busy={del.isPending && del.variables === b.id}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      {L.delete}
                    </ConfirmButton>
                  </TD>
                )}
              </TR>
            ))}
          </TBody>
        </Table>
      </DataState>
    </Card>
  );
}
