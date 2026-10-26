/**
 * Assets (/assets): protected asset inventory with software lists used for vulnerability matching.
 * ?asset=<id> opens an asset (linked from intel matches / advisories); ?asset=new opens the create form.
 * OWNER: frontend-intel.
 */
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Pencil, Plus, Search, Trash2 } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";
import { api } from "@/api/client";
import type { Asset, Page } from "@/api/types";
import { PageHeader, SeverityBadge } from "@/components/common";
import { ConfirmDialog } from "@/components/common/DangerConfirm";
import { OffsetPager } from "@/components/common/OffsetPager";
import { ApiErrorState, QueryView } from "@/components/common/QueryView";
import { useCan } from "@/components/common/RoleGate";
import { useUrlParams } from "@/components/common/urlState";
import {
  Badge,
  Button,
  Card,
  Dialog,
  EmptyState,
  Input,
  Select,
  Spinner,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { timeAgo } from "@/lib/format";
import { useLocal, useT } from "@/lib/i18n";
import type { AppRoute } from "@/routes";
import { AssetDialog } from "./AssetDialog";
import { ASSET_KINDS, useKindLabel } from "./labels";

const LIMIT = 50;

const strings = {
  ja: {
    title: "資産",
    desc: "保護対象の資産とソフトウェア構成。脆弱性インテリジェンスとの照合に使われます。",
    add: "資産を追加",
    search: "名前・ホスト名・IP で検索",
    kind: "種類",
    name: "名前",
    addresses: "ホスト / IP",
    software: "ソフトウェア",
    criticality: "重要度",
    owner: "担当者",
    updated: "更新",
    empty: "資産が登録されていません",
    emptyHint:
      "資産とソフトウェア（製品名・バージョン・CPE）を登録すると、KEV/EPSS と照合して優先度付きの助言が得られます。",
    deleteTitle: "資産を削除",
    deleteBody:
      "「{name}」を削除します。関連する脆弱性一致も参照できなくなる場合があります。この操作は取り消せません。",
    loadingAsset: "資産を読み込み中…",
    edit: "編集",
  },
  en: {
    title: "Assets",
    desc: "Protected assets and their software. Used for vulnerability-intel matching.",
    add: "Add asset",
    search: "Search name, hostname, IP",
    kind: "Kind",
    name: "Name",
    addresses: "Host / IP",
    software: "Software",
    criticality: "Criticality",
    owner: "Owner",
    updated: "Updated",
    empty: "No assets registered",
    emptyHint:
      "Register assets and their software (product, version, CPE) to get KEV/EPSS matching and prioritized advice.",
    deleteTitle: "Delete asset",
    deleteBody:
      'Delete "{name}". Related vulnerability matches may no longer be viewable. This cannot be undone.',
    loadingAsset: "Loading asset…",
    edit: "Edit",
  },
};

function AssetsPage() {
  const L = useLocal(strings);
  const t = useT();
  const can = useCan();
  const qc = useQueryClient();
  const kindLabel = useKindLabel();
  const [params, update] = useUrlParams();
  const q = params.get("q") ?? "";
  const kind = params.get("kind") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const assetParam = params.get("asset");
  const [qInput, setQInput] = useState(q);
  useEffect(() => setQInput(q), [q]);
  const [toDelete, setToDelete] = useState<Asset | null>(null);

  const list = useQuery({
    queryKey: ["assets", "list", { q, kind, offset }],
    queryFn: () => api.get<Page<Asset>>("/assets", { q, kind, limit: LIMIT, offset }),
    placeholderData: keepPreviousData,
  });

  const inList = assetParam ? list.data?.items.find((a) => a.id === assetParam) : undefined;
  const single = useQuery({
    queryKey: ["assets", "one", assetParam],
    queryFn: () => api.get<Asset>(`/assets/${encodeURIComponent(assetParam ?? "")}`),
    enabled: !!assetParam && assetParam !== "new" && !inList && !list.isLoading,
  });
  const dialogAsset = inList ?? single.data ?? null;

  const del = useMutation({
    mutationFn: (a: Asset) => api.delete(`/assets/${encodeURIComponent(a.id)}`),
    onSuccess: () => {
      setToDelete(null);
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["intel"] });
    },
  });

  const submitSearch = (e: FormEvent) => {
    e.preventDefault();
    update({ q: qInput.trim(), offset: null });
  };
  const closeDialog = () => update({ asset: null });

  return (
    <div>
      <PageHeader
        title={L.title}
        description={L.desc}
        actions={
          can.analyst && (
            <Button onClick={() => update({ asset: "new" })}>
              <Plus className="h-4 w-4" aria-hidden />
              {L.add}
            </Button>
          )
        }
      />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <form onSubmit={submitSearch} className="relative min-w-[16rem] flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted" aria-hidden />
          <Input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder={L.search}
            aria-label={L.search}
            className="pl-8"
          />
        </form>
        <Select
          aria-label={L.kind}
          value={kind}
          onChange={(e) => update({ kind: e.target.value, offset: null })}
        >
          <option value="">
            {L.kind}: {t("common.all")}
          </option>
          {ASSET_KINDS.map((k) => (
            <option key={k} value={k}>
              {kindLabel(k)}
            </option>
          ))}
        </Select>
      </div>

      <Card>
        <QueryView
          query={list}
          className="p-4"
          rows={6}
          isEmpty={(d) => d.items.length === 0}
          empty={<EmptyState title={L.empty} hint={L.emptyHint} icon={<Boxes className="h-6 w-6" />} />}
        >
          {(page) => (
            <>
              <Table>
                <THead>
                  <tr>
                    <TH>{L.name}</TH>
                    <TH>{L.kind}</TH>
                    <TH>{L.addresses}</TH>
                    <TH>{L.software}</TH>
                    <TH>{L.criticality}</TH>
                    <TH>{L.owner}</TH>
                    <TH>{L.updated}</TH>
                    <TH className="w-20" />
                  </tr>
                </THead>
                <TBody>
                  {page.items.map((a) => (
                    <TR key={a.id} className="cursor-pointer" onClick={() => update({ asset: a.id })}>
                      <TD>
                        <button
                          type="button"
                          className="text-left text-sm font-medium hover:text-accent hover:underline"
                          onClick={(e) => {
                            e.stopPropagation();
                            update({ asset: a.id });
                          }}
                        >
                          {a.name}
                        </button>
                        {a.tags.length > 0 && (
                          <div className="mt-0.5 flex flex-wrap gap-1">
                            {a.tags.slice(0, 4).map((tag) => (
                              <span key={tag} className="text-[10px] text-muted">
                                #{tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </TD>
                      <TD>
                        <Badge tone={a.kind === "llm_app" ? "ai" : "neutral"}>{kindLabel(a.kind)}</Badge>
                      </TD>
                      <TD className="font-mono text-xs">
                        {a.hostname && <div>{a.hostname}</div>}
                        <div className="text-muted">
                          {a.ips.slice(0, 3).join(", ")}
                          {a.ips.length > 3 && ` +${a.ips.length - 3}`}
                        </div>
                        {!a.hostname && !a.ips.length && <span className="text-muted">-</span>}
                      </TD>
                      <TD className="text-xs">
                        {a.software.length ? (
                          <>
                            <span className="tabular-nums font-medium">{a.software.length}</span>
                            <span className="ml-1.5 text-muted">
                              {a.software
                                .slice(0, 3)
                                .map((s) => [s.product, s.version].filter(Boolean).join(" "))
                                .join(", ")}
                              {a.software.length > 3 && " …"}
                            </span>
                          </>
                        ) : (
                          <span className="text-muted">0</span>
                        )}
                      </TD>
                      <TD>
                        <SeverityBadge severity={a.criticality} />
                      </TD>
                      <TD className="text-xs">{a.owner || <span className="text-muted">-</span>}</TD>
                      <TD className="whitespace-nowrap text-xs text-muted">{timeAgo(a.updated_at)}</TD>
                      <TD>
                        {can.analyst && (
                          <div className="flex justify-end gap-0.5">
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={`${L.edit}: ${a.name}`}
                              title={L.edit}
                              onClick={(e) => {
                                e.stopPropagation();
                                update({ asset: a.id });
                              }}
                            >
                              <Pencil className="h-3.5 w-3.5" aria-hidden />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="hover:text-sev-critical"
                              aria-label={`${t("common.delete")}: ${a.name}`}
                              title={t("common.delete")}
                              onClick={(e) => {
                                e.stopPropagation();
                                del.reset();
                                setToDelete(a);
                              }}
                            >
                              <Trash2 className="h-3.5 w-3.5" aria-hidden />
                            </Button>
                          </div>
                        )}
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

      {assetParam === "new" && can.analyst && (
        <AssetDialog key="new" open asset={null} readOnly={false} onClose={closeDialog} />
      )}
      {assetParam && assetParam !== "new" && dialogAsset && (
        <AssetDialog
          key={dialogAsset.id}
          open
          asset={dialogAsset}
          readOnly={!can.analyst}
          onClose={closeDialog}
        />
      )}
      {assetParam && assetParam !== "new" && !dialogAsset && (single.isLoading || single.error) ? (
        <Dialog open onClose={closeDialog} title={L.title}>
          {single.error ? (
            <ApiErrorState error={single.error} />
          ) : (
            <div className="flex items-center gap-2 text-sm text-muted">
              <Spinner /> {L.loadingAsset}
            </div>
          )}
        </Dialog>
      ) : null}

      <ConfirmDialog
        open={!!toDelete}
        title={L.deleteTitle}
        body={L.deleteBody.replace("{name}", toDelete?.name ?? "")}
        confirmLabel={t("common.delete")}
        busy={del.isPending}
        error={del.error}
        onConfirm={() => toDelete && del.mutate(toDelete)}
        onClose={() => setToDelete(null)}
      />
    </div>
  );
}

export const route: AppRoute = {
  path: "/assets",
  component: AssetsPage,
  nav: {
    label: { ja: "資産", en: "Assets" },
    icon: Boxes,
    section: "intel",
    order: 42,
  },
};
