/**
 * Notification channels (GET/POST /notify/channels, PATCH/DELETE /notify/channels/{id},
 * POST /notify/channels/{id}/test; admin). Secrets come back masked from the API and are never echoed.
 *
 * TODO(verify): config key names per channel kind are owned by the respond/notify module. The UI sends
 * `{url}` for webhook/slack/discord and `{smtp_host, smtp_port, smtp_username, smtp_password,
 * smtp_starttls, from_addr, to_addrs}` for email; the "extra JSON" field can add/override keys.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { BellPlus, BellRing, CircleCheck, CircleX, Send, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api } from "@/api/client";
import { type ChannelKind, type NotificationChannel, SEVERITIES, type Severity } from "@/api/types";
import type { NotificationChannelIn, NotifyTestResult } from "@/api/types-core";
import { Mono, SeverityBadge } from "@/components/common";
import { ConfirmButton } from "@/components/common/ConfirmButton";
import { DataState } from "@/components/common/DataState";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Dialog,
  Input,
  Label,
  Select,
  Table,
  TBody,
  TD,
  Textarea,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { errorMessage, useApiQuery } from "@/hooks/useApi";
import { useLocal, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { type Flash, MutationError } from "./shared";

const KINDS: ChannelKind[] = ["webhook", "slack", "discord", "email"];

const strings = {
  ja: {
    title: "通知チャネル",
    desc: "アラート・インシデント・承認依頼を送る先。指定した重大度以上のみ送信します。",
    add: "チャネルを追加",
    name: "名前",
    kind: "種類",
    target: "送信先",
    minSev: "最小重大度",
    andAbove: "以上",
    enabled: "有効",
    test: "テスト送信",
    testOk: "テスト送信に成功しました",
    testFail: "テスト送信に失敗しました",
    delete: "削除",
    deleted: "チャネルを削除しました",
    saved: "チャネルを追加しました",
    toggled: "チャネルを更新しました",
    empty: "通知チャネルはありません",
    emptyHint: "Webhook / Slack / Discord / メールを追加できます",
    dialog: "通知チャネルを追加",
    url: "Webhook URL",
    urlErr: "http(s):// で始まる URL を入力してください",
    smtpHost: "SMTP ホスト",
    smtpPort: "ポート",
    smtpUser: "ユーザー名",
    smtpPass: "パスワード",
    starttls: "STARTTLS を使う",
    from: "送信元アドレス",
    to: "宛先（カンマ区切り）",
    emailErr: "SMTP ホスト・送信元・宛先を入力してください",
    extra: "追加設定（JSON・任意）",
    extraHint: "上の項目に加えて config にマージされます",
    extraErr: "JSON オブジェクトとして解釈できません",
    secretNote: "秘密情報は保存後マスクされ、画面には再表示されません。",
    cancel: "キャンセル",
    save: "追加",
    on: "ON",
    off: "OFF",
  },
  en: {
    title: "Notification channels",
    desc: "Where alerts, incidents and approval requests are sent. Only at or above the chosen severity.",
    add: "Add channel",
    name: "Name",
    kind: "Kind",
    target: "Destination",
    minSev: "Min severity",
    andAbove: "and above",
    enabled: "Enabled",
    test: "Send test",
    testOk: "Test notification sent",
    testFail: "Test notification failed",
    delete: "Delete",
    deleted: "Channel deleted",
    saved: "Channel added",
    toggled: "Channel updated",
    empty: "No notification channels",
    emptyHint: "Add a webhook, Slack, Discord or email channel",
    dialog: "Add notification channel",
    url: "Webhook URL",
    urlErr: "Enter a URL starting with http(s)://",
    smtpHost: "SMTP host",
    smtpPort: "Port",
    smtpUser: "Username",
    smtpPass: "Password",
    starttls: "Use STARTTLS",
    from: "From address",
    to: "Recipients (comma separated)",
    emailErr: "SMTP host, from and recipients are required",
    extra: "Extra config (JSON, optional)",
    extraHint: "Merged into config on top of the fields above",
    extraErr: "Not a JSON object",
    secretNote: "Secrets are masked after saving and never shown again.",
    cancel: "Cancel",
    save: "Add",
    on: "ON",
    off: "OFF",
  },
};

const URL_PLACEHOLDER: Record<ChannelKind, string> = {
  webhook: "https://example.internal/hooks/tokiwa",
  slack: "https://hooks.slack.com/services/…",
  discord: "https://discord.com/api/webhooks/…",
  email: "",
};

interface Draft {
  kind: ChannelKind;
  name: string;
  min_severity: Severity;
  enabled: boolean;
  url: string;
  smtp_host: string;
  smtp_port: string;
  smtp_username: string;
  smtp_password: string;
  smtp_starttls: boolean;
  from_addr: string;
  to_addrs: string;
  extra: string;
}

const EMPTY: Draft = {
  kind: "webhook",
  name: "",
  min_severity: "high",
  enabled: true,
  url: "",
  smtp_host: "",
  smtp_port: "587",
  smtp_username: "",
  smtp_password: "",
  smtp_starttls: true,
  from_addr: "",
  to_addrs: "",
  extra: "",
};

function parseExtra(s: string): Record<string, unknown> | null {
  if (!s.trim()) return {};
  try {
    const v = JSON.parse(s) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Human summary of a channel's destination from its (masked) config. */
function destination(ch: NotificationChannel): string {
  const c = ch.config ?? {};
  if (ch.kind === "email") {
    const to = c.to_addrs ?? c.to ?? c.recipients;
    return Array.isArray(to) ? to.join(", ") : typeof to === "string" ? to : String(c.smtp_host ?? "-");
  }
  const url = c.url ?? c.webhook_url;
  return typeof url === "string" ? url : "-";
}

function CreateChannelDialog({
  open,
  onClose,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const L = useLocal(strings);
  const t = useT();
  const qc = useQueryClient();
  const [d, setD] = useState<Draft>(EMPTY);
  const [touched, setTouched] = useState(false);

  const extra = parseExtra(d.extra);
  const isEmail = d.kind === "email";
  const urlOk = isEmail || /^https?:\/\/\S+$/i.test(d.url.trim());
  const recipients = d.to_addrs
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const emailOk = !isEmail || (!!d.smtp_host.trim() && !!d.from_addr.trim() && recipients.length > 0);
  const nameOk = !!d.name.trim();
  const valid = nameOk && urlOk && emailOk && extra !== null;

  const m = useMutation({
    mutationFn: (body: NotificationChannelIn) => api.post<NotificationChannel>("/notify/channels", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["notify"] });
      setD(EMPTY);
      setTouched(false);
      onSaved();
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!valid || extra === null) return;
    const config: Record<string, unknown> = isEmail
      ? {
          smtp_host: d.smtp_host.trim(),
          smtp_port: Number(d.smtp_port) || 587,
          smtp_username: d.smtp_username.trim() || undefined,
          smtp_password: d.smtp_password || undefined,
          smtp_starttls: d.smtp_starttls,
          from_addr: d.from_addr.trim(),
          to_addrs: recipients,
        }
      : { url: d.url.trim() };
    m.mutate({
      kind: d.kind,
      name: d.name.trim(),
      min_severity: d.min_severity,
      enabled: d.enabled,
      config: { ...config, ...extra },
    });
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={L.dialog}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {L.cancel}
          </Button>
          <Button type="submit" form="channel-form" disabled={m.isPending}>
            {L.save}
          </Button>
        </>
      }
    >
      <form id="channel-form" onSubmit={submit} className="space-y-3" autoComplete="off">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[130px_1fr]">
          <div>
            <Label htmlFor="ch-kind">{L.kind}</Label>
            <Select
              id="ch-kind"
              value={d.kind}
              onChange={(e) => setD({ ...d, kind: e.target.value as ChannelKind })}
              className="w-full"
            >
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="ch-name">{L.name}</Label>
            <Input
              id="ch-name"
              value={d.name}
              onChange={(e) => setD({ ...d, name: e.target.value })}
              aria-invalid={touched && !nameOk}
              placeholder="soc-oncall"
            />
          </div>
        </div>

        {!isEmail ? (
          <div>
            <Label htmlFor="ch-url">{L.url}</Label>
            <Input
              id="ch-url"
              value={d.url}
              onChange={(e) => setD({ ...d, url: e.target.value })}
              placeholder={URL_PLACEHOLDER[d.kind]}
              aria-invalid={touched && !urlOk}
              className="font-mono text-xs"
            />
            {touched && !urlOk && <p className="mt-1 text-xs text-sev-critical">{L.urlErr}</p>}
          </div>
        ) : (
          <div className="space-y-3 rounded-md border border-line p-3">
            <div className="grid grid-cols-[1fr_90px] gap-3">
              <div>
                <Label htmlFor="ch-smtp">{L.smtpHost}</Label>
                <Input
                  id="ch-smtp"
                  value={d.smtp_host}
                  onChange={(e) => setD({ ...d, smtp_host: e.target.value })}
                  placeholder="smtp.example.com"
                />
              </div>
              <div>
                <Label htmlFor="ch-port">{L.smtpPort}</Label>
                <Input
                  id="ch-port"
                  inputMode="numeric"
                  value={d.smtp_port}
                  onChange={(e) => setD({ ...d, smtp_port: e.target.value.replace(/[^0-9]/g, "") })}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label htmlFor="ch-user">{L.smtpUser}</Label>
                <Input
                  id="ch-user"
                  value={d.smtp_username}
                  onChange={(e) => setD({ ...d, smtp_username: e.target.value })}
                  autoComplete="off"
                />
              </div>
              <div>
                <Label htmlFor="ch-pass">{L.smtpPass}</Label>
                <Input
                  id="ch-pass"
                  type="password"
                  value={d.smtp_password}
                  onChange={(e) => setD({ ...d, smtp_password: e.target.value })}
                  autoComplete="new-password"
                />
              </div>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={d.smtp_starttls}
                onChange={(e) => setD({ ...d, smtp_starttls: e.target.checked })}
                className="h-4 w-4 accent-[var(--tk-accent)]"
              />
              {L.starttls}
            </label>
            <div>
              <Label htmlFor="ch-from">{L.from}</Label>
              <Input
                id="ch-from"
                type="email"
                value={d.from_addr}
                onChange={(e) => setD({ ...d, from_addr: e.target.value })}
              />
            </div>
            <div>
              <Label htmlFor="ch-to">{L.to}</Label>
              <Input
                id="ch-to"
                value={d.to_addrs}
                onChange={(e) => setD({ ...d, to_addrs: e.target.value })}
              />
            </div>
            {touched && !emailOk && <p className="text-xs text-sev-critical">{L.emailErr}</p>}
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          <div>
            <Label htmlFor="ch-sev">{L.minSev}</Label>
            <Select
              id="ch-sev"
              value={d.min_severity}
              onChange={(e) => setD({ ...d, min_severity: e.target.value as Severity })}
              className="w-full"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {t(`severity.${s}`)} {L.andAbove}
                </option>
              ))}
            </Select>
          </div>
          <label className="flex items-end gap-2 pb-2 text-sm">
            <input
              type="checkbox"
              checked={d.enabled}
              onChange={(e) => setD({ ...d, enabled: e.target.checked })}
              className="h-4 w-4 accent-[var(--tk-accent)]"
            />
            {L.enabled}
          </label>
        </div>

        <div>
          <Label htmlFor="ch-extra">{L.extra}</Label>
          <Textarea
            id="ch-extra"
            rows={3}
            value={d.extra}
            onChange={(e) => setD({ ...d, extra: e.target.value })}
            placeholder='{"username": "TOKIWA"}'
            className="font-mono text-xs"
            aria-invalid={extra === null}
          />
          <p className={extra === null ? "mt-1 text-xs text-sev-critical" : "mt-1 text-[11px] text-muted"}>
            {extra === null ? L.extraErr : L.extraHint}
          </p>
        </div>
        <p className="text-[11px] text-muted">{L.secretNote}</p>
        <MutationError error={m.error} />
      </form>
    </Dialog>
  );
}

export function NotifyTab({ flash }: { flash: Flash }) {
  const L = useLocal(strings);
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [results, setResults] = useState<Record<string, NotifyTestResult>>({});
  const q = useApiQuery<NotificationChannel[]>(["notify", "channels"], "/notify/channels");

  const toggle = useMutation({
    mutationFn: (v: { id: string; enabled: boolean }) =>
      api.patch<NotificationChannel>(`/notify/channels/${v.id}`, { enabled: v.enabled }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["notify"] });
      flash(L.toggled);
    },
    onError: (e) => flash(errorMessage(e), "danger"),
  });
  const test = useMutation({
    mutationFn: (id: string) => api.post<NotifyTestResult>(`/notify/channels/${id}/test`),
    onSuccess: (r, id) => {
      setResults((prev) => ({ ...prev, [id]: r }));
      flash(r.ok ? L.testOk : `${L.testFail}: ${r.error ?? ""}`, r.ok ? "success" : "danger");
    },
    onError: (e, id) => {
      setResults((prev) => ({ ...prev, [id]: { ok: false, error: errorMessage(e) } }));
      flash(`${L.testFail}: ${errorMessage(e)}`, "danger");
    },
  });
  const del = useMutation({
    mutationFn: (id: string) => api.delete<unknown>(`/notify/channels/${id}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["notify"] });
      flash(L.deleted);
    },
    onError: (e) => flash(errorMessage(e), "danger"),
  });

  return (
    <Card>
      <CardHeader
        title={L.title}
        description={L.desc}
        actions={
          <Button size="sm" onClick={() => setOpen(true)}>
            <BellPlus className="h-3.5 w-3.5" />
            {L.add}
          </Button>
        }
      />
      <DataState
        loading={q.isLoading}
        error={q.error}
        empty={!!q.data && q.data.length === 0}
        emptyTitle={L.empty}
        emptyHint={L.emptyHint}
        emptyIcon={<BellRing className="h-6 w-6 opacity-60" />}
        onRetry={() => q.refetch()}
        className="p-4"
      >
        <Table>
          <THead>
            <tr>
              <TH>{L.name}</TH>
              <TH>{L.kind}</TH>
              <TH className="hidden lg:table-cell">{L.target}</TH>
              <TH>{L.minSev}</TH>
              <TH>{L.enabled}</TH>
              <TH className="w-[250px]" />
            </tr>
          </THead>
          <TBody>
            {(q.data ?? []).map((ch) => {
              const r = results[ch.id];
              return (
                <TR key={ch.id} className={cn(!ch.enabled && "opacity-70")}>
                  <TD className="font-medium">{ch.name}</TD>
                  <TD>
                    <Badge className="font-mono">{ch.kind}</Badge>
                  </TD>
                  <TD className="hidden max-w-[320px] truncate lg:table-cell" title={destination(ch)}>
                    <Mono className="text-muted">{destination(ch)}</Mono>
                  </TD>
                  <TD className="whitespace-nowrap">
                    <SeverityBadge severity={ch.min_severity} />
                    <span className="ml-1 text-[11px] text-muted">{L.andAbove}</span>
                  </TD>
                  <TD>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={ch.enabled}
                      aria-label={`${L.enabled}: ${ch.name}`}
                      disabled={toggle.isPending}
                      onClick={() => toggle.mutate({ id: ch.id, enabled: !ch.enabled })}
                      className={cn(
                        "inline-flex h-5 w-9 items-center rounded-full border transition-colors focus-visible:outline-2 focus-visible:outline-accent disabled:opacity-50",
                        ch.enabled ? "border-accent bg-accent" : "border-line bg-surface-2",
                      )}
                    >
                      <span
                        className={cn(
                          "h-3.5 w-3.5 rounded-full bg-surface shadow transition-transform",
                          ch.enabled ? "translate-x-[18px]" : "translate-x-[2px]",
                        )}
                      />
                    </button>
                    <span className="ml-1.5 text-[11px] text-muted">{ch.enabled ? L.on : L.off}</span>
                  </TD>
                  <TD className="text-right">
                    <span className="inline-flex items-center gap-1">
                      {r &&
                        (r.ok ? (
                          <CircleCheck className="h-4 w-4 text-accent" aria-label={L.testOk} />
                        ) : (
                          <span title={r.error ?? undefined}>
                            <CircleX className="h-4 w-4 text-sev-critical" aria-label={L.testFail} />
                          </span>
                        ))}
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => test.mutate(ch.id)}
                        disabled={test.isPending && test.variables === ch.id}
                      >
                        <Send className="h-3.5 w-3.5" />
                        {L.test}
                      </Button>
                      <ConfirmButton
                        onConfirm={() => del.mutate(ch.id)}
                        busy={del.isPending && del.variables === ch.id}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        {L.delete}
                      </ConfirmButton>
                    </span>
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      </DataState>
      <CreateChannelDialog
        open={open}
        onClose={() => setOpen(false)}
        onSaved={() => {
          setOpen(false);
          flash(L.saved);
        }}
      />
    </Card>
  );
}
