/**
 * Create / edit an asset, including its software inventory (vendor / product / version / CPE / ecosystem).
 * The inventory is what intel.matcher compares against vulnerability data, so precise versions and CPEs matter.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ClipboardPaste, Plus, Trash2 } from "lucide-react";
import { type FormEvent, useId, useState } from "react";
import { api } from "@/api/client";
import { type Asset, type AssetKind, SEVERITIES, type Severity } from "@/api/types";
import type { AssetPayload } from "@/api/types-intel";
import { ApiErrorState } from "@/components/common/QueryView";
import { Button, Dialog, Input, Label, Select, Spinner, Textarea } from "@/components/ui";
import { useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { ASSET_KINDS, ECOSYSTEMS, useKindLabel } from "./labels";
import { isBlankRow, looksLikeCpe, newRow, parseBulk, type SoftwareRow, toItems, toRows } from "./software";

const strings = {
  ja: {
    create: "資産を追加",
    edit: "資産を編集",
    view: "資産の詳細",
    name: "名前",
    kind: "種類",
    hostname: "ホスト名",
    ips: "IP アドレス",
    ipsHint: "カンマまたは空白区切り",
    criticality: "重要度",
    owner: "担当者",
    tags: "タグ",
    tagsHint: "カンマ区切り",
    notes: "メモ",
    software: "ソフトウェア",
    softwareHint:
      "脆弱性照合に使われます。CPE（cpe:2.3:a:vendor:product:version:…）があると精度が上がります。",
    vendor: "ベンダー",
    product: "製品名 *",
    version: "バージョン",
    cpe: "CPE",
    ecosystem: "エコシステム",
    addRow: "行を追加",
    removeRow: "この行を削除",
    bulk: "一括貼り付け",
    bulkHint: "1 行 1 パッケージ: pip freeze（name==1.0）/ npm（pkg@1.0）/「名前 バージョン」/ CPE 2.3",
    bulkEco: "エコシステム（任意）",
    bulkAdd: "取り込む",
    noSoftware: "ソフトウェアが登録されていません。",
    errName: "名前を入力してください。",
    errProduct: "製品名が空の行があります（行 {n}）。製品名を入力するか行を削除してください。",
    errIp: "IP アドレスの形式が正しくありません: {v}",
    warnCpe: "CPE の形式ではありません（cpe:2.3:… で始めてください）",
    readOnly: "閲覧のみ（編集にはアナリスト権限が必要です）",
  },
  en: {
    create: "Add asset",
    edit: "Edit asset",
    view: "Asset details",
    name: "Name",
    kind: "Kind",
    hostname: "Hostname",
    ips: "IP addresses",
    ipsHint: "comma or space separated",
    criticality: "Criticality",
    owner: "Owner",
    tags: "Tags",
    tagsHint: "comma separated",
    notes: "Notes",
    software: "Software",
    softwareHint:
      "Used for vulnerability matching. A CPE (cpe:2.3:a:vendor:product:version:…) improves accuracy.",
    vendor: "Vendor",
    product: "Product *",
    version: "Version",
    cpe: "CPE",
    ecosystem: "Ecosystem",
    addRow: "Add row",
    removeRow: "Remove this row",
    bulk: "Bulk paste",
    bulkHint: 'One package per line: pip freeze (name==1.0) / npm (pkg@1.0) / "name version" / CPE 2.3',
    bulkEco: "Ecosystem (optional)",
    bulkAdd: "Import",
    noSoftware: "No software registered.",
    errName: "Enter a name.",
    errProduct: "Row {n} has no product. Enter a product name or remove the row.",
    errIp: "Invalid IP address: {v}",
    warnCpe: "Not a CPE (should start with cpe:2.3:…)",
    readOnly: "Read-only (editing requires the analyst role)",
  },
};

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}(\/\d{1,2})?$/;
const IPV6 = /^[0-9a-f:]+(%\w+)?(\/\d{1,3})?$/i;

function splitList(s: string, sep: RegExp): string[] {
  return s
    .split(sep)
    .map((x) => x.trim())
    .filter(Boolean);
}

interface FormState {
  name: string;
  kind: AssetKind;
  hostname: string;
  ips: string;
  criticality: Severity;
  owner: string;
  tags: string;
  notes: string;
}

function initialForm(a: Asset | null): FormState {
  return {
    name: a?.name ?? "",
    kind: a?.kind ?? "host",
    hostname: a?.hostname ?? "",
    ips: (a?.ips ?? []).join(", "),
    criticality: a?.criticality ?? "medium",
    owner: a?.owner ?? "",
    tags: (a?.tags ?? []).join(", "),
    notes: a?.notes ?? "",
  };
}

export function AssetDialog({
  open,
  asset,
  readOnly,
  onClose,
  onSaved,
}: {
  open: boolean;
  asset: Asset | null;
  readOnly: boolean;
  onClose: () => void;
  onSaved?: (a: Asset) => void;
}) {
  const L = useLocal(strings);
  const t = useT();
  const kindLabel = useKindLabel();
  const qc = useQueryClient();
  const uid = useId();
  const [form, setForm] = useState<FormState>(() => initialForm(asset));
  const [rows, setRows] = useState<SoftwareRow[]>(() => toRows(asset?.software ?? []));
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [bulkEco, setBulkEco] = useState("");
  const [clientError, setClientError] = useState<string | null>(null);
  // State is initialised once per mount; the parent remounts this dialog (key=asset id) for each open.

  const save = useMutation({
    mutationFn: (payload: AssetPayload) =>
      asset
        ? api.patch<Asset>(`/assets/${encodeURIComponent(asset.id)}`, payload)
        : api.post<Asset>("/assets", payload),
    onSuccess: (saved) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["intel"] });
      onSaved?.(saved);
      onClose();
    },
  });

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setForm((f) => ({ ...f, [k]: v }));
  const setRow = (key: string, patch: Partial<SoftwareRow>) =>
    setRows((rs) => rs.map((r) => (r.key === key ? { ...r, ...patch } : r)));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (readOnly) return;
    setClientError(null);
    if (!form.name.trim()) return setClientError(L.errName);
    const ips = splitList(form.ips, /[\s,]+/);
    const badIp = ips.find((ip) => !IPV4.test(ip) && !(ip.includes(":") && IPV6.test(ip)));
    if (badIp) return setClientError(L.errIp.replace("{v}", badIp));
    const idx = rows.findIndex((r) => !isBlankRow(r) && !r.product.trim());
    if (idx >= 0) return setClientError(L.errProduct.replace("{n}", String(idx + 1)));
    save.mutate({
      name: form.name.trim(),
      kind: form.kind,
      hostname: form.hostname.trim() || null,
      ips,
      software: toItems(rows),
      criticality: form.criticality,
      owner: form.owner.trim() || null,
      tags: splitList(form.tags, /,/),
      notes: form.notes.trim() || null,
    });
  };

  const formId = `${uid}-form`;
  const title = readOnly ? L.view : asset ? L.edit : L.create;

  return (
    <Dialog
      open={open}
      onClose={save.isPending ? () => {} : onClose}
      wide
      title={title}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={save.isPending}>
            {readOnly ? t("common.close") : t("common.cancel")}
          </Button>
          {!readOnly && (
            <Button type="submit" form={formId} disabled={save.isPending}>
              {save.isPending && <Spinner className="h-3.5 w-3.5" />}
              {t("common.save")}
            </Button>
          )}
        </>
      }
    >
      <form id={formId} onSubmit={submit} className="space-y-5" noValidate>
        {readOnly && <p className="rounded-md bg-surface-2 px-3 py-2 text-xs text-muted">{L.readOnly}</p>}
        <fieldset disabled={readOnly || save.isPending} className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor={`${uid}-name`}>{L.name} *</Label>
              <Input
                id={`${uid}-name`}
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                required
                maxLength={255}
                aria-invalid={clientError === L.errName || undefined}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label htmlFor={`${uid}-kind`}>{L.kind}</Label>
                <Select
                  id={`${uid}-kind`}
                  className="w-full"
                  value={form.kind}
                  onChange={(e) => set("kind", e.target.value as AssetKind)}
                >
                  {ASSET_KINDS.map((k) => (
                    <option key={k} value={k}>
                      {kindLabel(k)}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <Label htmlFor={`${uid}-crit`}>{L.criticality}</Label>
                <Select
                  id={`${uid}-crit`}
                  className="w-full"
                  value={form.criticality}
                  onChange={(e) => set("criticality", e.target.value as Severity)}
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {t(`severity.${s}`)}
                    </option>
                  ))}
                </Select>
              </div>
            </div>
            <div>
              <Label htmlFor={`${uid}-host`}>{L.hostname}</Label>
              <Input
                id={`${uid}-host`}
                value={form.hostname}
                onChange={(e) => set("hostname", e.target.value)}
                className="font-mono"
              />
            </div>
            <div>
              <Label htmlFor={`${uid}-ips`}>
                {L.ips} <span className="font-normal">({L.ipsHint})</span>
              </Label>
              <Input
                id={`${uid}-ips`}
                value={form.ips}
                onChange={(e) => set("ips", e.target.value)}
                placeholder="10.0.0.5, 2001:db8::5"
                className="font-mono"
              />
            </div>
            <div>
              <Label htmlFor={`${uid}-owner`}>{L.owner}</Label>
              <Input id={`${uid}-owner`} value={form.owner} onChange={(e) => set("owner", e.target.value)} />
            </div>
            <div>
              <Label htmlFor={`${uid}-tags`}>
                {L.tags} <span className="font-normal">({L.tagsHint})</span>
              </Label>
              <Input
                id={`${uid}-tags`}
                value={form.tags}
                onChange={(e) => set("tags", e.target.value)}
                placeholder="prod, dmz"
              />
            </div>
            <div className="sm:col-span-2">
              <Label htmlFor={`${uid}-notes`}>{L.notes}</Label>
              <Textarea
                id={`${uid}-notes`}
                rows={2}
                value={form.notes}
                onChange={(e) => set("notes", e.target.value)}
              />
            </div>
          </div>

          <section className="space-y-2">
            <div className="flex flex-wrap items-end justify-between gap-2">
              <div>
                <h4 className="text-sm font-semibold">
                  {L.software} <span className="font-normal text-muted">({toItems(rows).length})</span>
                </h4>
                <p className="text-xs text-muted">{L.softwareHint}</p>
              </div>
              {!readOnly && (
                <div className="flex gap-1.5">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setBulkOpen((v) => !v)}
                    aria-expanded={bulkOpen}
                  >
                    <ClipboardPaste className="h-3.5 w-3.5" aria-hidden />
                    {L.bulk}
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setRows((rs) => [...rs, newRow()])}>
                    <Plus className="h-3.5 w-3.5" aria-hidden />
                    {L.addRow}
                  </Button>
                </div>
              )}
            </div>

            {bulkOpen && !readOnly && (
              <div className="space-y-2 rounded-md border border-line bg-surface-2/40 p-3">
                <p className="text-xs text-muted">{L.bulkHint}</p>
                <Textarea
                  rows={5}
                  value={bulkText}
                  onChange={(e) => setBulkText(e.target.value)}
                  className="font-mono text-xs"
                  spellCheck={false}
                  aria-label={L.bulk}
                  placeholder={
                    "django==4.2.7\nexpress@4.18.2\nopenssl 3.0.13\ncpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
                  }
                />
                <div className="flex flex-wrap items-center gap-2">
                  <Select aria-label={L.bulkEco} value={bulkEco} onChange={(e) => setBulkEco(e.target.value)}>
                    <option value="">{L.bulkEco}</option>
                    {ECOSYSTEMS.map((e) => (
                      <option key={e} value={e}>
                        {e}
                      </option>
                    ))}
                  </Select>
                  <Button
                    size="sm"
                    disabled={!bulkText.trim()}
                    onClick={() => {
                      const parsed = parseBulk(bulkText, bulkEco);
                      setRows((rs) => [...rs.filter((r) => !isBlankRow(r)), ...parsed]);
                      setBulkText("");
                      setBulkOpen(false);
                    }}
                  >
                    {L.bulkAdd}
                  </Button>
                </div>
              </div>
            )}

            {rows.length === 0 ? (
              <p className="rounded-md border border-dashed border-line px-3 py-4 text-center text-xs text-muted">
                {L.noSoftware}
              </p>
            ) : (
              <div className="overflow-x-auto rounded-md border border-line">
                <table className="w-full min-w-[720px] text-xs">
                  <thead className="bg-surface-2/60 text-left text-muted">
                    <tr>
                      <th className="w-8 px-2 py-1.5 font-medium">#</th>
                      <th className="px-1 py-1.5 font-medium">{L.vendor}</th>
                      <th className="px-1 py-1.5 font-medium">{L.product}</th>
                      <th className="w-28 px-1 py-1.5 font-medium">{L.version}</th>
                      <th className="px-1 py-1.5 font-medium">{L.cpe}</th>
                      <th className="w-32 px-1 py-1.5 font-medium">{L.ecosystem}</th>
                      <th className="w-9" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {rows.map((r, i) => {
                      const cpeBad = !!r.cpe.trim() && !looksLikeCpe(r.cpe);
                      const productMissing = !isBlankRow(r) && !r.product.trim();
                      const cell = "h-8 rounded px-2 text-xs";
                      return (
                        <tr key={r.key}>
                          <td className="px-2 text-muted tabular-nums">{i + 1}</td>
                          <td className="px-1 py-1">
                            <Input
                              className={cell}
                              value={r.vendor}
                              aria-label={`${L.vendor} ${i + 1}`}
                              onChange={(e) => setRow(r.key, { vendor: e.target.value })}
                            />
                          </td>
                          <td className="px-1 py-1">
                            <Input
                              className={cn(cell, productMissing && "border-sev-critical")}
                              value={r.product}
                              aria-label={`${L.product} ${i + 1}`}
                              aria-invalid={productMissing || undefined}
                              onChange={(e) => setRow(r.key, { product: e.target.value })}
                            />
                          </td>
                          <td className="px-1 py-1">
                            <Input
                              className={cn(cell, "font-mono")}
                              value={r.version}
                              aria-label={`${L.version} ${i + 1}`}
                              onChange={(e) => setRow(r.key, { version: e.target.value })}
                            />
                          </td>
                          <td className="px-1 py-1">
                            <Input
                              className={cn(cell, "font-mono", cpeBad && "border-sev-medium")}
                              value={r.cpe}
                              placeholder="cpe:2.3:a:…"
                              title={cpeBad ? L.warnCpe : undefined}
                              aria-label={`${L.cpe} ${i + 1}`}
                              onChange={(e) => setRow(r.key, { cpe: e.target.value })}
                            />
                          </td>
                          <td className="px-1 py-1">
                            <Input
                              className={cell}
                              list={`${uid}-eco`}
                              value={r.ecosystem}
                              aria-label={`${L.ecosystem} ${i + 1}`}
                              onChange={(e) => setRow(r.key, { ecosystem: e.target.value })}
                            />
                          </td>
                          <td className="px-1">
                            {!readOnly && (
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-7 w-7"
                                aria-label={`${L.removeRow} (${i + 1})`}
                                title={L.removeRow}
                                onClick={() => setRows((rs) => rs.filter((x) => x.key !== r.key))}
                              >
                                <Trash2 className="h-3.5 w-3.5" aria-hidden />
                              </Button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                <datalist id={`${uid}-eco`}>
                  {ECOSYSTEMS.map((e) => (
                    <option key={e} value={e} />
                  ))}
                </datalist>
              </div>
            )}
          </section>
        </fieldset>

        {clientError && (
          <p role="alert" className="text-sm text-sev-critical">
            {clientError}
          </p>
        )}
        {save.error ? <ApiErrorState error={save.error} /> : null}
      </form>
    </Dialog>
  );
}
