/**
 * Create / edit a Sigma rule. "Validate" calls POST /rules/validate; saving re-validates server-side (422 on error).
 * Built-in (file-based) rules are read-only here — duplicate them to customise.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Copy, ShieldCheck } from "lucide-react";
import { useId, useState } from "react";
import { api } from "@/api/client";
import type { Rule } from "@/api/types";
import type { RuleValidation } from "@/api/types-intel";
import { ApiErrorState } from "@/components/common/QueryView";
import { Button, Dialog, Label, Select, Spinner } from "@/components/ui";
import { useLang, useLocal, useT } from "@/lib/i18n";
import { duplicateSigma, RuleSourceBadge, RuleStatusBadge, sigmaTemplate, useRuleLabels } from "./labels";
import { SigmaEditor, ValidationResult } from "./SigmaEditor";

const strings = {
  ja: {
    create: "Sigma ルールを作成",
    edit: "Sigma ルールを編集",
    view: "Sigma ルール",
    content: "ルール本文（Sigma YAML）",
    validate: "検証",
    status: "保存後の状態",
    builtin: "組み込みルールはファイル由来のため読み取り専用です。複製して編集してください。",
    duplicate: "複製して編集",
    proposedNote: "提案中のルールです。保存しても有効化されません。レビュー後に「承認」してください。",
    draftNote: "LLM の提案から作成します。内容を確認し、検証してから保存してください（既定は無効状態）。",
    hits: "ヒット数",
  },
  en: {
    create: "Create Sigma rule",
    edit: "Edit Sigma rule",
    view: "Sigma rule",
    content: "Rule body (Sigma YAML)",
    validate: "Validate",
    status: "Status after save",
    builtin: "Built-in rules come from files and are read-only. Duplicate to customise.",
    duplicate: "Duplicate & edit",
    proposedNote: "This rule is a proposal. Saving does not enable it — approve it after review.",
    draftNote: "Created from an LLM proposal. Review and validate before saving (defaults to disabled).",
    hits: "Hits",
  },
};

export function RuleEditorDialog({
  rule,
  draft,
  readOnly,
  onClose,
  onSaved,
}: {
  rule: Rule | null;
  /** Prefill for a new rule (e.g. an LLM proposal that is not in the review queue). */
  draft?: { content: string; fromLlm?: boolean };
  readOnly?: boolean;
  onClose: () => void;
  onSaved?: (r: Rule) => void;
}) {
  const L = useLocal(strings);
  const t = useT();
  const { lang } = useLang();
  const labels = useRuleLabels();
  const qc = useQueryClient();
  const uid = useId();
  const [dup, setDup] = useState<string | null>(null);
  const editingRule = dup !== null ? null : rule;
  const builtinLocked = !!editingRule && editingRule.source === "builtin";
  const locked = readOnly || builtinLocked;
  const [content, setContent] = useState(() => rule?.content ?? draft?.content ?? sigmaTemplate(lang));
  const [status, setStatus] = useState<"active" | "disabled">(() =>
    rule?.status === "disabled" || draft?.fromLlm ? "disabled" : "active",
  );
  const [validation, setValidation] = useState<RuleValidation | null>(null);

  const validate = useMutation({
    mutationFn: () => api.post<RuleValidation>("/rules/validate", { content }),
    onSuccess: setValidation,
  });

  const save = useMutation({
    mutationFn: () => {
      if (editingRule) {
        const body: Record<string, unknown> = { content };
        if (editingRule.status === "active" || editingRule.status === "disabled") body.status = status;
        return api.patch<Rule>(`/rules/${encodeURIComponent(editingRule.id)}`, body);
      }
      return api.post<Rule>("/rules", { kind: "sigma", content, status });
    },
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      onSaved?.(r);
      onClose();
    },
  });

  const isProposal = editingRule?.status === "proposed";
  const title = locked ? L.view : editingRule ? L.edit : L.create;
  const showStatus = !locked && !isProposal && editingRule?.status !== "rejected";

  return (
    <Dialog
      open
      wide
      onClose={save.isPending ? () => {} : onClose}
      title={
        <span className="flex flex-wrap items-center gap-2">
          {title}
          {editingRule && <RuleStatusBadge status={editingRule.status} />}
          {editingRule && <RuleSourceBadge source={editingRule.source} />}
        </span>
      }
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={save.isPending}>
            {locked ? t("common.close") : t("common.cancel")}
          </Button>
          {builtinLocked && !readOnly && (
            <Button
              variant="outline"
              onClick={() => {
                const copy = duplicateSigma(content);
                setDup(copy);
                setContent(copy);
                setStatus("disabled");
                setValidation(null);
              }}
            >
              <Copy className="h-4 w-4" aria-hidden />
              {L.duplicate}
            </Button>
          )}
          {!locked && (
            <>
              <Button
                variant="outline"
                onClick={() => validate.mutate()}
                disabled={validate.isPending || !content.trim()}
              >
                {validate.isPending ? (
                  <Spinner className="h-3.5 w-3.5" />
                ) : (
                  <ShieldCheck className="h-4 w-4" aria-hidden />
                )}
                {L.validate}
              </Button>
              <Button onClick={() => save.mutate()} disabled={save.isPending || !content.trim()}>
                {save.isPending && <Spinner className="h-3.5 w-3.5" />}
                {t("common.save")}
              </Button>
            </>
          )}
        </>
      }
    >
      <div className="space-y-3">
        {builtinLocked && !readOnly && (
          <p className="rounded-md bg-surface-2 px-3 py-2 text-xs text-muted">{L.builtin}</p>
        )}
        {isProposal && !locked && (
          <p className="rounded-md border border-ai/30 bg-ai/10 px-3 py-2 text-xs text-ai">
            {L.proposedNote}
          </p>
        )}
        {!editingRule && draft?.fromLlm && dup === null && (
          <p className="rounded-md border border-ai/30 bg-ai/10 px-3 py-2 text-xs text-ai">{L.draftNote}</p>
        )}
        {editingRule && (
          <p className="text-xs text-muted">
            {L.hits}: <span className="tabular-nums text-fg">{editingRule.hit_count}</span>
          </p>
        )}
        <SigmaEditor
          id={`${uid}-content`}
          label={L.content}
          value={content}
          readOnly={locked}
          onChange={(v) => {
            setContent(v);
            setValidation(null);
          }}
        />
        {showStatus && (
          <div className="flex items-center gap-2">
            <Label htmlFor={`${uid}-status`} className="mb-0">
              {L.status}
            </Label>
            <Select
              id={`${uid}-status`}
              value={status}
              onChange={(e) => setStatus(e.target.value as "active" | "disabled")}
            >
              <option value="active">{labels.status("active")}</option>
              <option value="disabled">{labels.status("disabled")}</option>
            </Select>
          </div>
        )}
        {validation && <ValidationResult result={validation} />}
        {validate.error ? <ApiErrorState error={validate.error} /> : null}
        {save.error ? <ApiErrorState error={save.error} /> : null}
      </div>
    </Dialog>
  );
}
