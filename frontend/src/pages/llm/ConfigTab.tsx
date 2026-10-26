/**
 * LLM runtime configuration. PUT /llm/config is a partial update, so only changed fields are sent.
 * API keys are write-only: inputs are never prefilled, values are cleared after saving, and the API never
 * returns them (at most a "*_set" boolean).
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, KeyRound, PlugZap, XCircle } from "lucide-react";
import { type FormEvent, useId, useState } from "react";
import { api } from "@/api/client";
import {
  EFFORTS,
  type Effort,
  type LLMConfig,
  type LLMConfigUpdate,
  type LLMProviderName,
  type LLMTestResult,
} from "@/api/types-intel";
import { InlineNotice, useFlash } from "@/components/common/InlineNotice";
import { ApiErrorState, LoadingRows } from "@/components/common/QueryView";
import { useCan } from "@/components/common/RoleGate";
import { ToggleSwitch } from "@/components/common/ToggleSwitch";
import { Badge, Button, Card, CardBody, CardHeader, Input, Label, Select, Spinner } from "@/components/ui";
import { formatUsd } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export const LLM_CONFIG_KEY = ["llm", "config"];

const strings = {
  ja: {
    status: "現在の状態",
    provider: "プロバイダ",
    available: "利用可能",
    unavailable: "利用不可（ルールベースにフォールバック）",
    spent: "本日の費用",
    budget: "日次予算",
    settings: "設定",
    settingsDesc: "保存すると LLM ゲートウェイが再構築され、以降の呼び出しに反映されます。",
    adminOnly: "設定の変更は管理者のみ可能です。",
    providerAuto: "auto（API キーがあれば Anthropic、なければ mock）",
    providerAnthropic: "Anthropic（Claude）",
    providerOpenai: "OpenAI 互換（Ollama / vLLM などローカル LLM）",
    providerMock: "mock（LLM を呼ばない・テスト用）",
    modelFast: "軽量モデル（一次トリアージ）",
    modelDeep: "高性能モデル（昇格・詳細分析）",
    effortFast: "思考量（軽量）",
    effortDeep: "思考量（高性能）",
    budgetLabel: "日次予算（USD）",
    budgetHint: "超過すると LLM を呼ばずルールベース判定になります",
    language: "出力言語",
    fallbacks: "拒否時のフォールバック",
    fallbacksHint: "安全分類器で拒否された場合にサーバー側で代替モデルを使う（高性能ティア）",
    cache: "プロンプトキャッシュ",
    cacheHint: "システムプロンプトをキャッシュして費用と遅延を削減",
    credentials: "認証情報（書き込み専用）",
    credentialsHint: "API キーは保存後も表示されません。変更する場合のみ入力してください。",
    anthropicKey: "Anthropic API キー",
    openaiUrl: "OpenAI 互換エンドポイント URL",
    openaiKey: "OpenAI 互換 API キー",
    keySet: "設定済み — 変更する場合のみ入力",
    keyStored: "設定済み",
    keyUnknown: "未変更（入力すると上書き）",
    urlUnchanged: "未変更（例: http://localhost:11434/v1）",
    save: "保存",
    reset: "元に戻す",
    saved: "保存しました",
    noChanges: "変更はありません",
    test: "接続テスト",
    testDesc: "最小の構造化呼び出しを 1 回行い、プロバイダへの到達性を確認します（少額の費用が発生します）。",
    runTest: "テストを実行",
    ok: "接続成功",
    ng: "接続失敗",
    model: "モデル",
    latency: "応答時間",
  },
  en: {
    status: "Current status",
    provider: "Provider",
    available: "Available",
    unavailable: "Unavailable (falling back to rules)",
    spent: "Spent today",
    budget: "Daily budget",
    settings: "Settings",
    settingsDesc: "Saving rebuilds the LLM gateway; subsequent calls use the new settings.",
    adminOnly: "Only administrators can change settings.",
    providerAuto: "auto (Anthropic if an API key is set, otherwise mock)",
    providerAnthropic: "Anthropic (Claude)",
    providerOpenai: "OpenAI-compatible (local LLM: Ollama / vLLM …)",
    providerMock: "mock (no LLM calls, for testing)",
    modelFast: "Fast model (first-pass triage)",
    modelDeep: "Deep model (escalation / analysis)",
    effortFast: "Effort (fast)",
    effortDeep: "Effort (deep)",
    budgetLabel: "Daily budget (USD)",
    budgetHint: "When exceeded, the LLM is not called and rule-based decisions are used",
    language: "Output language",
    fallbacks: "Refusal fallback",
    fallbacksHint: "Use a server-side fallback model when a safety classifier refuses (deep tier)",
    cache: "Prompt caching",
    cacheHint: "Cache system prompts to cut cost and latency",
    credentials: "Credentials (write-only)",
    credentialsHint: "API keys are never shown after saving. Fill in only to change them.",
    anthropicKey: "Anthropic API key",
    openaiUrl: "OpenAI-compatible endpoint URL",
    openaiKey: "OpenAI-compatible API key",
    keySet: "Set — fill in only to replace",
    keyStored: "Set",
    keyUnknown: "Unchanged (typing overwrites it)",
    urlUnchanged: "Unchanged (e.g. http://localhost:11434/v1)",
    save: "Save",
    reset: "Reset",
    saved: "Saved",
    noChanges: "No changes",
    test: "Connection test",
    testDesc:
      "Makes one minimal structured call to check that the provider is reachable (incurs a small cost).",
    runTest: "Run test",
    ok: "Connected",
    ng: "Failed",
    model: "Model",
    latency: "Latency",
  },
};

const MODEL_SUGGESTIONS = ["claude-haiku-5-5", "claude-opus-5-5"];

type Editable = Required<
  Pick<
    LLMConfigUpdate,
    | "provider"
    | "model_fast"
    | "model_deep"
    | "effort_fast"
    | "effort_deep"
    | "daily_budget_usd"
    | "output_language"
    | "enable_fallbacks"
    | "prompt_cache"
  >
>;

function fromConfig(c: LLMConfig): Editable {
  return {
    provider: (c.provider as LLMProviderName) ?? "auto",
    model_fast: c.model_fast ?? "",
    model_deep: c.model_deep ?? "",
    effort_fast: c.effort_fast ?? "low",
    effort_deep: c.effort_deep ?? "medium",
    daily_budget_usd: c.daily_budget_usd ?? 0,
    output_language: c.output_language ?? "ja",
    enable_fallbacks: !!c.enable_fallbacks,
    prompt_cache: !!c.prompt_cache,
  };
}

export function BudgetMeter({ spent, budget }: { spent: number; budget: number }) {
  const ratio = budget > 0 ? Math.min(1, spent / budget) : 0;
  const color = ratio >= 1 ? "bg-sev-critical" : ratio >= 0.8 ? "bg-sev-high" : "bg-accent";
  return (
    <div className="space-y-1">
      <div className="flex items-baseline justify-between gap-2 text-sm tabular-nums">
        <span className="font-semibold">{formatUsd(spent)}</span>
        <span className="text-xs text-muted">/ {formatUsd(budget)}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-surface-2" aria-hidden>
        <div className={cn("h-full rounded-full", color)} style={{ width: `${Math.max(2, ratio * 100)}%` }} />
      </div>
      <div className="text-[11px] text-muted tabular-nums">{Math.round(ratio * 100)}%</div>
    </div>
  );
}

function ConfigForm({ config }: { config: LLMConfig }) {
  const L = useLocal(strings);
  const can = useCan();
  const qc = useQueryClient();
  const uid = useId();
  const initial = fromConfig(config);
  const [form, setForm] = useState<Editable>(initial);
  const [budgetText, setBudgetText] = useState(String(initial.daily_budget_usd));
  const [anthropicKey, setAnthropicKey] = useState("");
  const [openaiKey, setOpenaiKey] = useState("");
  const [openaiUrl, setOpenaiUrl] = useState("");
  const [notice, flash] = useFlash();
  const readOnly = !can.admin;

  const set = <K extends keyof Editable>(k: K, v: Editable[K]) => setForm((f) => ({ ...f, [k]: v }));

  const budget = Number(budgetText);
  const budgetInvalid = budgetText.trim() === "" || !Number.isFinite(budget) || budget < 0;
  const changes: LLMConfigUpdate = {};
  for (const k of Object.keys(form) as (keyof Editable)[]) {
    if (k === "daily_budget_usd") continue;
    if (form[k] !== initial[k]) (changes as Record<string, unknown>)[k] = form[k];
  }
  if (!budgetInvalid && budget !== initial.daily_budget_usd) changes.daily_budget_usd = budget;
  if (anthropicKey.trim()) changes.anthropic_api_key = anthropicKey.trim();
  if (openaiKey.trim()) changes.openai_api_key = openaiKey.trim();
  if (openaiUrl.trim()) changes.openai_base_url = openaiUrl.trim();
  const dirty = Object.keys(changes).length > 0;

  const save = useMutation({
    mutationFn: (body: LLMConfigUpdate) => api.put<LLMConfig>("/llm/config", body),
    onSuccess: () => {
      setAnthropicKey("");
      setOpenaiKey("");
      flash(L.saved);
      qc.invalidateQueries({ queryKey: LLM_CONFIG_KEY });
      qc.invalidateQueries({ queryKey: ["system"] });
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (readOnly || budgetInvalid) return;
    if (!dirty) return flash(L.noChanges, "info");
    save.mutate(changes);
  };

  const effortSelect = (id: string, value: Effort, onChange: (v: Effort) => void) => (
    <Select id={id} className="w-full" value={value} onChange={(e) => onChange(e.target.value as Effort)}>
      {EFFORTS.map((e) => (
        <option key={e} value={e}>
          {e}
        </option>
      ))}
    </Select>
  );

  return (
    <Card>
      <CardHeader title={L.settings} description={readOnly ? L.adminOnly : L.settingsDesc} />
      <form onSubmit={submit} autoComplete="off">
        <fieldset disabled={readOnly || save.isPending}>
          <CardBody className="space-y-5">
            <div>
              <Label htmlFor={`${uid}-provider`}>{L.provider}</Label>
              <Select
                id={`${uid}-provider`}
                className="w-full"
                value={form.provider}
                onChange={(e) => set("provider", e.target.value as LLMProviderName)}
              >
                <option value="auto">{L.providerAuto}</option>
                <option value="anthropic">{L.providerAnthropic}</option>
                <option value="openai_compat">{L.providerOpenai}</option>
                <option value="mock">{L.providerMock}</option>
              </Select>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <Label htmlFor={`${uid}-mf`}>{L.modelFast}</Label>
                <Input
                  id={`${uid}-mf`}
                  list={`${uid}-models`}
                  className="font-mono"
                  value={form.model_fast}
                  onChange={(e) => set("model_fast", e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor={`${uid}-md`}>{L.modelDeep}</Label>
                <Input
                  id={`${uid}-md`}
                  list={`${uid}-models`}
                  className="font-mono"
                  value={form.model_deep}
                  onChange={(e) => set("model_deep", e.target.value)}
                />
              </div>
              <datalist id={`${uid}-models`}>
                {MODEL_SUGGESTIONS.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
              <div>
                <Label htmlFor={`${uid}-ef`}>{L.effortFast}</Label>
                {effortSelect(`${uid}-ef`, form.effort_fast, (v) => set("effort_fast", v))}
              </div>
              <div>
                <Label htmlFor={`${uid}-ed`}>{L.effortDeep}</Label>
                {effortSelect(`${uid}-ed`, form.effort_deep, (v) => set("effort_deep", v))}
              </div>
              <div>
                <Label htmlFor={`${uid}-budget`}>{L.budgetLabel}</Label>
                <Input
                  id={`${uid}-budget`}
                  type="number"
                  inputMode="decimal"
                  min={0}
                  step={0.5}
                  value={budgetText}
                  aria-invalid={budgetInvalid || undefined}
                  aria-describedby={`${uid}-budget-hint`}
                  className={cn(budgetInvalid && "border-sev-critical")}
                  onChange={(e) => setBudgetText(e.target.value)}
                />
                <p id={`${uid}-budget-hint`} className="mt-1 text-[11px] text-muted">
                  {L.budgetHint}
                </p>
              </div>
              <div>
                <Label htmlFor={`${uid}-lang`}>{L.language}</Label>
                <Select
                  id={`${uid}-lang`}
                  className="w-full"
                  value={form.output_language}
                  onChange={(e) => set("output_language", e.target.value as "ja" | "en")}
                >
                  <option value="ja">日本語 (ja)</option>
                  <option value="en">English (en)</option>
                </Select>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              {(
                [
                  ["enable_fallbacks", L.fallbacks, L.fallbacksHint],
                  ["prompt_cache", L.cache, L.cacheHint],
                ] as const
              ).map(([key, label, hint]) => (
                <div
                  key={key}
                  className="flex items-start justify-between gap-3 rounded-md border border-line p-3"
                >
                  <div>
                    <div className="text-sm font-medium">{label}</div>
                    <div className="text-[11px] text-muted">{hint}</div>
                  </div>
                  <ToggleSwitch
                    checked={form[key]}
                    disabled={readOnly || save.isPending}
                    label={label}
                    onChange={(v) => set(key, v)}
                  />
                </div>
              ))}
            </div>

            <div className="space-y-3 rounded-md border border-line p-3">
              <div className="flex items-start gap-2">
                <KeyRound className="mt-0.5 h-4 w-4 text-muted" aria-hidden />
                <div>
                  <div className="text-sm font-medium">{L.credentials}</div>
                  <div className="text-[11px] text-muted">{L.credentialsHint}</div>
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="sm:col-span-2">
                  <Label htmlFor={`${uid}-akey`}>
                    {L.anthropicKey}{" "}
                    {config.anthropic_api_key_set && <Badge tone="accent">{L.keyStored}</Badge>}
                  </Label>
                  <Input
                    id={`${uid}-akey`}
                    type="password"
                    autoComplete="new-password"
                    spellCheck={false}
                    className="font-mono"
                    value={anthropicKey}
                    placeholder={config.anthropic_api_key_set ? L.keySet : L.keyUnknown}
                    onChange={(e) => setAnthropicKey(e.target.value)}
                  />
                </div>
                <div>
                  <Label htmlFor={`${uid}-ourl`}>{L.openaiUrl}</Label>
                  <Input
                    id={`${uid}-ourl`}
                    type="url"
                    spellCheck={false}
                    className="font-mono"
                    value={openaiUrl}
                    placeholder={config.openai_base_url || L.urlUnchanged}
                    onChange={(e) => setOpenaiUrl(e.target.value)}
                  />
                </div>
                <div>
                  <Label htmlFor={`${uid}-okey`}>
                    {L.openaiKey} {config.openai_api_key_set && <Badge tone="accent">{L.keyStored}</Badge>}
                  </Label>
                  <Input
                    id={`${uid}-okey`}
                    type="password"
                    autoComplete="new-password"
                    spellCheck={false}
                    className="font-mono"
                    value={openaiKey}
                    placeholder={config.openai_api_key_set ? L.keySet : L.keyUnknown}
                    onChange={(e) => setOpenaiKey(e.target.value)}
                  />
                </div>
              </div>
            </div>

            {save.error ? <ApiErrorState error={save.error} /> : null}
            {!readOnly && (
              <div className="flex items-center justify-end gap-3">
                {notice && <InlineNotice tone={notice.tone}>{notice.text}</InlineNotice>}
                <Button
                  variant="ghost"
                  disabled={!dirty || save.isPending}
                  onClick={() => {
                    setForm(initial);
                    setBudgetText(String(initial.daily_budget_usd));
                    setAnthropicKey("");
                    setOpenaiKey("");
                    setOpenaiUrl("");
                  }}
                >
                  {L.reset}
                </Button>
                <Button type="submit" disabled={!dirty || budgetInvalid || save.isPending}>
                  {save.isPending && <Spinner className="h-3.5 w-3.5" />}
                  {L.save}
                </Button>
              </div>
            )}
          </CardBody>
        </fieldset>
      </form>
    </Card>
  );
}

function ConnectionTest() {
  const L = useLocal(strings);
  const can = useCan();
  const test = useMutation({ mutationFn: () => api.post<LLMTestResult>("/llm/test") });
  const r = test.data;
  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            <PlugZap className="h-4 w-4 text-ai" aria-hidden />
            {L.test}
          </span>
        }
        description={L.testDesc}
        actions={
          can.admin && (
            <Button variant="outline" size="sm" onClick={() => test.mutate()} disabled={test.isPending}>
              {test.isPending && <Spinner className="h-3.5 w-3.5" />}
              {L.runTest}
            </Button>
          )
        }
      />
      {(r || test.error) && (
        <CardBody className="space-y-2 text-sm">
          {test.error ? <ApiErrorState error={test.error} /> : null}
          {r && (
            <div role="status" className="space-y-1.5">
              <div
                className={cn(
                  "flex items-center gap-1.5 font-medium",
                  r.ok ? "text-accent" : "text-sev-critical",
                )}
              >
                {r.ok ? (
                  <CheckCircle2 className="h-4 w-4" aria-hidden />
                ) : (
                  <XCircle className="h-4 w-4" aria-hidden />
                )}
                {r.ok ? L.ok : L.ng}
              </div>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
                <dt className="text-muted">{L.provider}</dt>
                <dd className="font-mono">{r.provider}</dd>
                <dt className="text-muted">{L.model}</dt>
                <dd className="font-mono">{r.model}</dd>
                <dt className="text-muted">{L.latency}</dt>
                <dd className="tabular-nums">{Math.round(r.latency_ms)} ms</dd>
              </dl>
              {r.error && (
                <pre className="whitespace-pre-wrap break-all rounded border border-sev-critical/30 bg-sev-critical/10 p-2 font-mono text-[11px] text-sev-critical">
                  {r.error}
                </pre>
              )}
            </div>
          )}
        </CardBody>
      )}
    </Card>
  );
}

export function ConfigTab() {
  const L = useLocal(strings);
  const q = useQuery({ queryKey: LLM_CONFIG_KEY, queryFn: () => api.get<LLMConfig>("/llm/config") });
  if (q.isLoading) return <LoadingRows rows={8} />;
  if (q.error) return <ApiErrorState error={q.error} />;
  const c = q.data;
  if (!c) return null;
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
      {/* Remount the form when the stored settings change (not on spend updates) so it shows saved values. */}
      <ConfigForm
        key={JSON.stringify([
          fromConfig(c),
          c.anthropic_api_key_set,
          c.openai_api_key_set,
          c.openai_base_url,
        ])}
        config={c}
      />
      <div className="space-y-4">
        <Card>
          <CardHeader title={L.status} />
          <CardBody className="space-y-4">
            <div className="space-y-1">
              <div className="text-[11px] text-muted">{L.provider}</div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm">{c.provider}</span>
                {c.available ? (
                  <Badge tone="accent">
                    <CheckCircle2 className="h-3 w-3" aria-hidden />
                    {L.available}
                  </Badge>
                ) : (
                  <Badge tone="warn">
                    <XCircle className="h-3 w-3" aria-hidden />
                    {L.unavailable}
                  </Badge>
                )}
              </div>
            </div>
            <div className="space-y-1">
              <div className="text-[11px] text-muted">
                {L.spent} / {L.budget}
              </div>
              <BudgetMeter spent={c.spent_today_usd ?? 0} budget={c.daily_budget_usd ?? 0} />
            </div>
          </CardBody>
        </Card>
        <ConnectionTest />
      </div>
    </div>
  );
}
