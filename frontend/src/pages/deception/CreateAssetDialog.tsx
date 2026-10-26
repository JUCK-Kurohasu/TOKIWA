/** Create dialog for Mirage assets: pick a kind, then a form tailored to that kind. */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Bot, ShieldAlert } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api } from "@/api/client";
import type { DeceptionAsset, DeceptionKind } from "@/api/types";
import { DECEPTION_KINDS, type DeceptionAssetIn } from "@/api/types-ops";
import { Notice } from "@/components/common/OpsKit";
import { deceptionKindDescription, deceptionKindLabel } from "@/components/common/opsLabels";
import { Button, Dialog, ErrorState, Input, Label, Textarea } from "@/components/ui";
import { useLabel, useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { kindFields, kindIcon } from "./kinds";

const strings = {
  ja: {
    title: "デセプション資産を作成",
    kind: "種類",
    name: "名前",
    namePh: "例: 管理画面の AI カナリア",
    path: "配信パス",
    pathOptional: "配置先パス（任意）",
    pathHintLabyrinth: "末尾を * にするとプレフィックス一致（例: /internal/docs/*）",
    token: "カナリア値（トークン）",
    tokenHint: "空欄で自動生成（推奨）。実在サービスでは無効な一意の値になります。",
    template: "本文テンプレート（任意）",
    templateHint: "空欄で既定テンプレート（日英）を使用します。プレビューで実際の本文を確認できます。",
    description: "メモ（任意）",
    enabled: "作成後すぐに有効にする",
    create: "作成",
    cancel: "キャンセル",
    errName: "名前を入力してください",
    errPath: "パスは / で始めてください（例: /.env）",
    errPathRequired: "この種類では配信パスが必要です",
    aiNoteTitle: "AI カナリアの仕組み",
    aiNote:
      "このパスで配信されるページに、人間には見えない隠し指示（HTML コメント・不可視要素など）を埋め込みます。指示どおりにトークンを使ったリクエストが来た場合のみ AI エージェントと断定します。",
    ethics:
      "偽データのみを配信します。攻撃者の端末で何かを実行させる仕組み（ビーコン・エクスプロイト）は含みません。",
  },
  en: {
    title: "Create deception asset",
    kind: "Kind",
    name: "Name",
    namePh: "e.g. AI canary on the admin page",
    path: "Served path",
    pathOptional: "Planted at path (optional)",
    pathHintLabyrinth: "End with * for a prefix match (e.g. /internal/docs/*)",
    token: "Canary value (token)",
    tokenHint: "Leave empty to generate (recommended). It is unique and never valid for a real service.",
    template: "Content template (optional)",
    templateHint: "Leave empty for the default (ja/en) template. Use Preview to see the exact body served.",
    description: "Note (optional)",
    enabled: "Enable immediately",
    create: "Create",
    cancel: "Cancel",
    errName: "Enter a name",
    errPath: "The path must start with / (e.g. /.env)",
    errPathRequired: "This kind needs a served path",
    aiNoteTitle: "How AI canaries work",
    aiNote:
      "The page served at this path embeds a hidden instruction (HTML comment, invisible element …) that humans never see. Only a request that uses the token exactly as instructed is attributed to an AI agent.",
    ethics:
      "Only fake data is served. Nothing is executed on the attacker's machine (no beacons, no exploits).",
  },
};

export function CreateAssetDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (asset: DeceptionAsset) => void;
}) {
  const L = useLocal(strings);
  const label = useLabel();
  const qc = useQueryClient();
  const [kind, setKind] = useState<DeceptionKind>("ai_canary");
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [token, setToken] = useState("");
  const [template, setTemplate] = useState("");
  const [description, setDescription] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [formError, setFormError] = useState<string | null>(null);
  const cfg = kindFields[kind];

  const m = useMutation({
    mutationFn: (body: DeceptionAssetIn) => api.post<DeceptionAsset>("/deception/assets", body),
    onSuccess: (asset) => {
      void qc.invalidateQueries({ queryKey: ["deception"] });
      onCreated(asset);
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    const p = path.trim();
    if (!name.trim()) return setFormError(L.errName);
    if (cfg.path === "required" && !p) return setFormError(L.errPathRequired);
    if (p && !p.startsWith("/")) return setFormError(L.errPath);
    setFormError(null);
    m.mutate({
      kind,
      name: name.trim(),
      path: cfg.path !== "hidden" && p ? p : null,
      token: cfg.token && token.trim() ? token.trim() : null,
      content_template: cfg.template && template.trim() ? template : null,
      description: description.trim() || null,
      enabled,
    });
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={L.title}
      wide
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {L.cancel}
          </Button>
          <Button type="submit" form="create-deception" disabled={m.isPending}>
            {L.create}
          </Button>
        </>
      }
    >
      <form id="create-deception" onSubmit={submit} className="space-y-4">
        <fieldset>
          <legend className="mb-2 text-xs font-medium text-muted">{L.kind}</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {DECEPTION_KINDS.map((k) => {
              const Icon = kindIcon[k];
              const selected = k === kind;
              const ai = k === "ai_canary";
              return (
                <label
                  key={k}
                  className={cn(
                    "flex cursor-pointer gap-2.5 rounded-md border p-3 transition-colors has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-accent",
                    selected
                      ? ai
                        ? "border-ai/60 bg-ai/10"
                        : "border-accent/60 bg-accent-soft"
                      : "border-line hover:bg-surface-2",
                  )}
                >
                  <input
                    type="radio"
                    name="deception-kind"
                    value={k}
                    checked={selected}
                    onChange={() => setKind(k)}
                    className="sr-only"
                  />
                  <Icon
                    className={cn("mt-0.5 h-4 w-4 shrink-0", ai ? "text-ai" : "text-accent")}
                    aria-hidden
                  />
                  <span className="min-w-0">
                    <span className={cn("block text-sm font-medium", ai && "text-ai")}>
                      {label(deceptionKindLabel[k])}
                    </span>
                    <span className="block text-xs leading-relaxed text-muted">
                      {label(deceptionKindDescription[k])}
                    </span>
                  </span>
                </label>
              );
            })}
          </div>
        </fieldset>

        {kind === "ai_canary" && (
          <Notice tone="ai" icon={<Bot className="h-4 w-4 text-ai" aria-hidden />} title={L.aiNoteTitle}>
            {L.aiNote}
          </Notice>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="da-name">{L.name}</Label>
            <Input
              id="da-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={L.namePh}
            />
          </div>
          {cfg.path !== "hidden" && (
            <div>
              <Label htmlFor="da-path">{cfg.path === "required" ? L.path : L.pathOptional}</Label>
              <Input
                id="da-path"
                className="font-mono"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder={cfg.pathPh}
              />
              {kind === "labyrinth" && <p className="mt-1 text-[11px] text-muted">{L.pathHintLabyrinth}</p>}
            </div>
          )}
          {cfg.token && (
            <div className="sm:col-span-2">
              <Label htmlFor="da-token">{L.token}</Label>
              <Input
                id="da-token"
                className="font-mono"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              <p className="mt-1 text-[11px] text-muted">{L.tokenHint}</p>
            </div>
          )}
          {cfg.template && (
            <div className="sm:col-span-2">
              <Label htmlFor="da-template">{L.template}</Label>
              <Textarea
                id="da-template"
                rows={5}
                className="font-mono text-xs"
                value={template}
                onChange={(e) => setTemplate(e.target.value)}
                spellCheck={false}
              />
              <p className="mt-1 text-[11px] text-muted">{L.templateHint}</p>
            </div>
          )}
          <div className="sm:col-span-2">
            <Label htmlFor="da-desc">{L.description}</Label>
            <Input id="da-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
        </div>

        <label htmlFor="da-enabled" className="flex items-center gap-2 text-sm">
          <input
            id="da-enabled"
            type="checkbox"
            className="accent-[var(--tk-accent)]"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          {L.enabled}
        </label>

        {formError && <p className="text-xs text-sev-critical">{formError}</p>}
        {m.error && <ErrorState error={m.error} />}

        <p className="flex items-start gap-1.5 text-[11px] text-muted">
          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
          {L.ethics}
        </p>
      </form>
    </Dialog>
  );
}
