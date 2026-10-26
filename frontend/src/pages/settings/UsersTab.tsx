/** Users: list, create, delete (GET/POST /users, DELETE /users/{id}; admin). */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, KeySquare, Trash2, UserPlus, Users } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api } from "@/api/client";
import { ROLES, type Role, type User, type UserCreate, type UserUpdate } from "@/api/types-core";
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
  TH,
  THead,
  TR,
} from "@/components/ui";
import { errorMessage, useApiQuery } from "@/hooks/useApi";
import { useCurrentUserId } from "@/hooks/useRole";
import { formatDateTime, timeAgo } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { type Flash, MutationError, RoleBadge } from "./shared";

const USERNAME_RE = /^[A-Za-z0-9_.-]{3,64}$/;

const strings = {
  ja: {
    title: "ユーザー",
    desc: "UI にログインできるアカウント。ロールで操作範囲が決まります。",
    add: "ユーザーを追加",
    username: "ユーザー名",
    role: "ロール",
    created: "作成",
    lastLogin: "最終ログイン",
    never: "未ログイン",
    you: "あなた",
    delete: "削除",
    selfDelete: "自分自身は削除できません",
    deleted: "ユーザーを削除しました",
    createdMsg: "ユーザーを作成しました",
    roleChanged: "ロールを変更しました",
    selfRole: "自分自身のロールはここでは変更できません",
    resetPw: "パスワード再設定",
    newPassword: "新しいパスワード",
    pwChanged: "パスワードを変更しました",
    save: "保存",
    empty: "ユーザーがいません",
    dialog: "ユーザーを追加",
    password: "パスワード",
    passwordHint: "10 文字以上",
    usernameHint: "3〜64 文字の英数字と _ . -",
    usernameErr: "ユーザー名は 3〜64 文字の英数字と _ . - のみ使えます",
    passwordErr: "パスワードは 10 文字以上にしてください",
    show: "表示",
    hide: "隠す",
    cancel: "キャンセル",
    create: "作成",
    role_viewer: "viewer — 閲覧のみ",
    role_analyst: "analyst — アラート・インシデント・対処を操作",
    role_admin: "admin — ユーザー・トークン・設定も管理",
  },
  en: {
    title: "Users",
    desc: "Accounts that can sign in to the UI. The role decides what they can change.",
    add: "Add user",
    username: "Username",
    role: "Role",
    created: "Created",
    lastLogin: "Last login",
    never: "never",
    you: "you",
    delete: "Delete",
    selfDelete: "You cannot delete yourself",
    deleted: "User deleted",
    createdMsg: "User created",
    roleChanged: "Role updated",
    selfRole: "You cannot change your own role here",
    resetPw: "Reset password",
    newPassword: "New password",
    pwChanged: "Password changed",
    save: "Save",
    empty: "No users",
    dialog: "Add user",
    password: "Password",
    passwordHint: "At least 10 characters",
    usernameHint: "3–64 letters, digits, _ . -",
    usernameErr: "Use 3–64 letters, digits, _ . - only",
    passwordErr: "Password must be at least 10 characters",
    show: "Show",
    hide: "Hide",
    cancel: "Cancel",
    create: "Create",
    role_viewer: "viewer — read only",
    role_analyst: "analyst — work alerts, incidents and actions",
    role_admin: "admin — also users, tokens and settings",
  },
};

function CreateUserDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const L = useLocal(strings);
  const qc = useQueryClient();
  const [form, setForm] = useState<UserCreate>({ username: "", password: "", role: "analyst" });
  const [show, setShow] = useState(false);
  const [touched, setTouched] = useState(false);
  const userOk = USERNAME_RE.test(form.username);
  const passOk = form.password.length >= 10;

  const m = useMutation({
    mutationFn: (body: UserCreate) => api.post<User>("/users", body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["users"] });
      setForm({ username: "", password: "", role: "analyst" });
      setTouched(false);
      onCreated();
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (userOk && passOk) m.mutate(form);
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
          <Button type="submit" form="user-form" disabled={m.isPending}>
            {L.create}
          </Button>
        </>
      }
    >
      <form id="user-form" onSubmit={submit} className="space-y-3" autoComplete="off">
        <div>
          <Label htmlFor="u-name">{L.username}</Label>
          <Input
            id="u-name"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            aria-invalid={touched && !userOk}
            autoComplete="off"
          />
          <p
            className={touched && !userOk ? "mt-1 text-xs text-sev-critical" : "mt-1 text-[11px] text-muted"}
          >
            {touched && !userOk ? L.usernameErr : L.usernameHint}
          </p>
        </div>
        <div>
          <Label htmlFor="u-pass">{L.password}</Label>
          <div className="flex gap-1.5">
            <Input
              id="u-pass"
              type={show ? "text" : "password"}
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              aria-invalid={touched && !passOk}
              autoComplete="new-password"
            />
            <Button
              variant="outline"
              size="icon"
              className="h-9 w-9 shrink-0"
              onClick={() => setShow(!show)}
              aria-label={show ? L.hide : L.show}
            >
              {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </Button>
          </div>
          <p
            className={touched && !passOk ? "mt-1 text-xs text-sev-critical" : "mt-1 text-[11px] text-muted"}
          >
            {touched && !passOk ? L.passwordErr : L.passwordHint}
          </p>
        </div>
        <div>
          <Label htmlFor="u-role">{L.role}</Label>
          <Select
            id="u-role"
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value as Role })}
            className="w-full"
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {L[`role_${r}`]}
              </option>
            ))}
          </Select>
        </div>
        <MutationError error={m.error} />
      </form>
    </Dialog>
  );
}

export function UsersTab({ flash }: { flash: Flash }) {
  const L = useLocal(strings);
  const qc = useQueryClient();
  const me = useCurrentUserId();
  const [open, setOpen] = useState(false);
  const q = useApiQuery<User[]>(["users"], "/users");

  const [pwUser, setPwUser] = useState<User | null>(null);

  const del = useMutation({
    mutationFn: (id: string) => api.delete<unknown>(`/users/${id}`),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["users"] });
      flash(L.deleted);
    },
    onError: (e) => flash(errorMessage(e), "danger"),
  });
  const setRole = useMutation({
    mutationFn: (v: { id: string; role: Role }) =>
      api.patch<User>(`/users/${v.id}`, { role: v.role } satisfies UserUpdate),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["users"] });
      flash(L.roleChanged);
    },
    // 409 = would demote the last admin
    onError: (e) => flash(errorMessage(e), "danger"),
  });

  return (
    <Card>
      <CardHeader
        title={L.title}
        description={L.desc}
        actions={
          <Button size="sm" onClick={() => setOpen(true)}>
            <UserPlus className="h-3.5 w-3.5" />
            {L.add}
          </Button>
        }
      />
      <DataState
        loading={q.isLoading}
        error={q.error}
        empty={!!q.data && q.data.length === 0}
        emptyTitle={L.empty}
        emptyIcon={<Users className="h-6 w-6 opacity-60" />}
        onRetry={() => q.refetch()}
        className="p-4"
      >
        <Table>
          <THead>
            <tr>
              <TH>{L.username}</TH>
              <TH>{L.role}</TH>
              <TH className="hidden md:table-cell">{L.created}</TH>
              <TH>{L.lastLogin}</TH>
              <TH className="w-[260px]" />
            </tr>
          </THead>
          <TBody>
            {(q.data ?? []).map((u) => (
              <TR key={u.id}>
                <TD>
                  <span className="font-medium">{u.username}</span>
                  {u.id === me && (
                    <Badge tone="accent" className="ml-2">
                      {L.you}
                    </Badge>
                  )}
                </TD>
                <TD>
                  {u.id === me ? (
                    <span title={L.selfRole}>
                      <RoleBadge role={u.role} />
                    </span>
                  ) : (
                    <Select
                      value={u.role}
                      onChange={(e) => setRole.mutate({ id: u.id, role: e.target.value as Role })}
                      disabled={setRole.isPending && setRole.variables?.id === u.id}
                      className="h-7 font-mono text-xs"
                      aria-label={`${L.role}: ${u.username}`}
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                    </Select>
                  )}
                </TD>
                <TD className="hidden whitespace-nowrap text-xs text-muted md:table-cell">
                  {formatDateTime(u.created_at)}
                </TD>
                <TD className="whitespace-nowrap text-xs text-muted" title={formatDateTime(u.last_login)}>
                  {u.last_login ? timeAgo(u.last_login) : L.never}
                </TD>
                <TD className="whitespace-nowrap text-right">
                  <Button size="sm" variant="ghost" onClick={() => setPwUser(u)}>
                    <KeySquare className="h-3.5 w-3.5" />
                    {L.resetPw}
                  </Button>
                  <ConfirmButton
                    onConfirm={() => del.mutate(u.id)}
                    disabled={u.id === me}
                    busy={del.isPending && del.variables === u.id}
                    title={u.id === me ? L.selfDelete : undefined}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    {L.delete}
                  </ConfirmButton>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </DataState>
      <CreateUserDialog
        open={open}
        onClose={() => setOpen(false)}
        onCreated={() => {
          setOpen(false);
          flash(L.createdMsg);
        }}
      />
      <ResetPasswordDialog
        user={pwUser}
        onClose={() => setPwUser(null)}
        onDone={() => {
          setPwUser(null);
          flash(L.pwChanged);
        }}
      />
    </Card>
  );
}

function ResetPasswordDialog({
  user,
  onClose,
  onDone,
}: {
  user: User | null;
  onClose: () => void;
  onDone: () => void;
}) {
  const L = useLocal(strings);
  const [pw, setPw] = useState("");
  const [touched, setTouched] = useState(false);
  const ok = pw.length >= 10;
  const m = useMutation({
    mutationFn: (v: { id: string; password: string }) =>
      api.patch<User>(`/users/${v.id}`, { password: v.password } satisfies UserUpdate),
    onSuccess: () => {
      setPw("");
      setTouched(false);
      onDone();
    },
  });
  function close() {
    setPw("");
    setTouched(false);
    m.reset();
    onClose();
  }
  function submit(e: FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (user && ok) m.mutate({ id: user.id, password: pw });
  }
  return (
    <Dialog
      open={!!user}
      onClose={close}
      title={`${L.resetPw}: ${user?.username ?? ""}`}
      footer={
        <>
          <Button variant="ghost" onClick={close}>
            {L.cancel}
          </Button>
          <Button type="submit" form="pw-form" disabled={m.isPending}>
            {L.save}
          </Button>
        </>
      }
    >
      <form id="pw-form" onSubmit={submit} className="space-y-2" autoComplete="off">
        <Label htmlFor="pw-new">{L.newPassword}</Label>
        <Input
          id="pw-new"
          type="password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          autoComplete="new-password"
          aria-invalid={touched && !ok}
        />
        <p className={touched && !ok ? "text-xs text-sev-critical" : "text-[11px] text-muted"}>
          {touched && !ok ? L.passwordErr : L.passwordHint}
        </p>
        <MutationError error={m.error} />
      </form>
    </Dialog>
  );
}
