/**
 * API tokens for sensors / gate / automation (GET/POST /tokens, DELETE /tokens/{id}; admin).
 * The plain-text token is returned once by POST and only kept in component state until the dialog closes.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Ban, KeyRound, Plus } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api } from "@/api/client";
import type { ApiToken } from "@/api/types";
import {
  API_TOKEN_SCOPES,
  type ApiTokenCreate,
  type ApiTokenCreated,
  type ApiTokenScope,
} from "@/api/types-core";
import { Mono } from "@/components/common";
import { ConfirmButton } from "@/components/common/ConfirmButton";
import { DataState } from "@/components/common/DataState";
import { SecretReveal } from "@/components/common/SecretReveal";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Dialog,
  Input,
  Label,
  Table,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "@/components/ui";
import { errorMessage, useApiQuery } from "@/hooks/useApi";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { type Flash, MutationError } from "./shared";

const strings = {
  ja: {
    title: "API トークン",
    desc: "センサー（tokiwa agent）・ゲート・自動化ツールが使うトークン。平文は作成時に一度だけ表示されます。",
    add: "トークンを作成",
    name: "名前",
    prefix: "識別子",
    scopes: "スコープ",
    created: "作成",
    lastUsed: "最終使用",
    never: "未使用",
    status: "状態",
    active: "有効",
    revoked: "失効",
    revoke: "失効させる",
    revokedMsg: "トークンを失効させました",
    empty: "トークンはまだありません",
    emptyHint: "センサーやゲートを接続するにはトークンを作成してください",
    dialog: "API トークンを作成",
    nameHint: "用途がわかる名前（例: gate-1, web01-agent）",
    nameErr: "名前を入力してください（64 文字以内）",
    scopeErr: "スコープを 1 つ以上選んでください",
    scope_ingest: "イベント送信（エージェント・ゲート）",
    scope_gate: "ゲートポリシーの取得",
    scope_read: "読み取り専用 API（自動化）",
    cancel: "キャンセル",
    create: "作成",
    done: "保存したので閉じる",
    createdTitle: "トークンを作成しました",
    usage: "使い方",
    usageHeader: "HTTP ヘッダ",
    usageEnv: "環境変数（ゲート / エージェント）",
  },
  en: {
    title: "API tokens",
    desc: "Tokens used by sensors (tokiwa agent), the gate and automation. The secret is shown only once on creation.",
    add: "Create token",
    name: "Name",
    prefix: "Prefix",
    scopes: "Scopes",
    created: "Created",
    lastUsed: "Last used",
    never: "never",
    status: "Status",
    active: "active",
    revoked: "revoked",
    revoke: "Revoke",
    revokedMsg: "Token revoked",
    empty: "No tokens yet",
    emptyHint: "Create a token to connect sensors or the gate",
    dialog: "Create API token",
    nameHint: "Something that identifies the client (e.g. gate-1, web01-agent)",
    nameErr: "Enter a name (max 64 characters)",
    scopeErr: "Select at least one scope",
    scope_ingest: "Push events (agent, gate)",
    scope_gate: "Pull gate policy",
    scope_read: "Read-only API (automation)",
    cancel: "Cancel",
    create: "Create",
    done: "I saved it — close",
    createdTitle: "Token created",
    usage: "Usage",
    usageHeader: "HTTP header",
    usageEnv: "Environment (gate / agent)",
  },
};

function CreateTokenDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const L = useLocal(strings);
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<ApiTokenScope[]>(["ingest", "gate"]);
  const [touched, setTouched] = useState(false);
  const [created, setCreated] = useState<ApiTokenCreated | null>(null);
  const nameOk = name.trim().length >= 1 && name.trim().length <= 64;

  const m = useMutation({
    mutationFn: (body: ApiTokenCreate) => api.post<ApiTokenCreated>("/tokens", body),
    onSuccess: (t) => {
      setCreated(t);
      void qc.invalidateQueries({ queryKey: ["tokens"] });
    },
  });

  function close() {
    // Drop the secret from memory as soon as the dialog closes.
    setCreated(null);
    setName("");
    setScopes(["ingest", "gate"]);
    setTouched(false);
    m.reset();
    onClose();
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (nameOk && scopes.length) m.mutate({ name: name.trim(), scopes });
  }

  if (created) {
    return (
      <Dialog
        open={open}
        onClose={close}
        title={L.createdTitle}
        footer={<Button onClick={close}>{L.done}</Button>}
      >
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-medium">{created.name}</span>
            {created.scopes.map((s) => (
              <Badge key={s} className="font-mono">
                {s}
              </Badge>
            ))}
          </div>
          <SecretReveal secret={created.token} />
          <div className="space-y-1.5 text-xs">
            <div className="font-medium text-muted">{L.usage}</div>
            <div className="text-[11px] text-muted">{L.usageHeader}</div>
            <pre className="overflow-x-auto rounded-md border border-line bg-bg p-2 font-mono">
              X-Tokiwa-Token: {"<token>"}
            </pre>
            <div className="text-[11px] text-muted">{L.usageEnv}</div>
            <pre className="overflow-x-auto rounded-md border border-line bg-bg p-2 font-mono">
              {"TOKIWA_GATE__INGEST_TOKEN=<token>\nTOKIWA_AGENT__INGEST_TOKEN=<token>"}
            </pre>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      open={open}
      onClose={close}
      title={L.dialog}
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            {L.cancel}
          </Button>
          <Button type="submit" form="token-form" disabled={m.isPending}>
            <KeyRound className="h-3.5 w-3.5" />
            {L.create}
          </Button>
        </>
      }
    >
      <form id="token-form" onSubmit={submit} className="space-y-3">
        <div>
          <Label htmlFor="t-name">{L.name}</Label>
          <Input
            id="t-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={64}
            aria-invalid={touched && !nameOk}
          />
          <p
            className={touched && !nameOk ? "mt-1 text-xs text-sev-critical" : "mt-1 text-[11px] text-muted"}
          >
            {touched && !nameOk ? L.nameErr : L.nameHint}
          </p>
        </div>
        <fieldset>
          <legend className="mb-1 text-xs font-medium text-muted">{L.scopes}</legend>
          <div className="space-y-1.5">
            {API_TOKEN_SCOPES.map((s) => (
              <label key={s} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={scopes.includes(s)}
                  onChange={(e) =>
                    setScopes(e.target.checked ? [...scopes, s] : scopes.filter((x) => x !== s))
                  }
                  className="h-4 w-4 accent-[var(--tk-accent)]"
                />
                <Mono className="w-14">{s}</Mono>
                <span className="text-muted">{L[`scope_${s}`]}</span>
              </label>
            ))}
          </div>
          {touched && scopes.length === 0 && <p className="mt-1 text-xs text-sev-critical">{L.scopeErr}</p>}
        </fieldset>
        <MutationError error={m.error} />
      </form>
    </Dialog>
  );
}

export function TokensTab({ flash }: { flash: Flash }) {
  const L = useLocal(strings);
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const q = useApiQuery<ApiToken[]>(["tokens"], "/tokens");
  const rows = [...(q.data ?? [])].sort(
    (a, b) => Number(a.revoked) - Number(b.revoked) || b.created_at.localeCompare(a.created_at),
  );

  const revoke = useMutation({
    mutationFn: (id: string) => api.delete<unknown>(`/tokens/${id}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["tokens"] });
      flash(L.revokedMsg);
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
            <Plus className="h-3.5 w-3.5" />
            {L.add}
          </Button>
        }
      />
      <DataState
        loading={q.isLoading}
        error={q.error}
        empty={!!q.data && rows.length === 0}
        emptyTitle={L.empty}
        emptyHint={L.emptyHint}
        emptyIcon={<KeyRound className="h-6 w-6 opacity-60" />}
        onRetry={() => q.refetch()}
        className="p-4"
      >
        <Table>
          <THead>
            <tr>
              <TH>{L.name}</TH>
              <TH>{L.prefix}</TH>
              <TH>{L.scopes}</TH>
              <TH className="hidden md:table-cell">{L.created}</TH>
              <TH>{L.lastUsed}</TH>
              <TH>{L.status}</TH>
              <TH className="w-[170px]" />
            </tr>
          </THead>
          <TBody>
            {rows.map((t) => (
              <TR key={t.id} className={cn(t.revoked && "opacity-60")}>
                <TD className="font-medium">{t.name}</TD>
                <TD>
                  <Mono>{t.prefix}…</Mono>
                </TD>
                <TD>
                  <span className="flex flex-wrap gap-1">
                    {t.scopes.map((s) => (
                      <Badge key={s} className="font-mono">
                        {s}
                      </Badge>
                    ))}
                  </span>
                </TD>
                <TD className="hidden whitespace-nowrap text-xs text-muted md:table-cell">
                  {formatDateTime(t.created_at)}
                </TD>
                <TD className="whitespace-nowrap text-xs text-muted" title={formatDateTime(t.last_used)}>
                  {t.last_used ? timeAgo(t.last_used) : L.never}
                </TD>
                <TD>{t.revoked ? <Badge>{L.revoked}</Badge> : <Badge tone="accent">{L.active}</Badge>}</TD>
                <TD className="text-right">
                  {!t.revoked && (
                    <ConfirmButton
                      onConfirm={() => revoke.mutate(t.id)}
                      busy={revoke.isPending && revoke.variables === t.id}
                    >
                      <Ban className="h-3.5 w-3.5" />
                      {L.revoke}
                    </ConfirmButton>
                  )}
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </DataState>
      <CreateTokenDialog open={open} onClose={() => setOpen(false)} />
    </Card>
  );
}
