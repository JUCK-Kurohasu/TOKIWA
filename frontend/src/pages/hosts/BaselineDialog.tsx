/** Create a port baseline (allowed listener). POST /hosts/baselines */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useState } from "react";
import { api } from "@/api/client";
import type { PortBaseline, PortBaselineIn } from "@/api/types-core";
import { Button, Dialog, ErrorState, Input, Label, Select, Textarea } from "@/components/ui";
import { useLocal } from "@/lib/i18n";

export interface BaselineDraft {
  host: string;
  protocol: string;
  port: string;
  process_name: string;
  allow_public: boolean;
  note: string;
}

export const EMPTY_DRAFT: BaselineDraft = {
  host: "",
  protocol: "tcp",
  port: "",
  process_name: "",
  allow_public: false,
  note: "",
};

// The server normalizes tcp6/udp6 to tcp/udp (baselines are per transport, not address family).
const PROTOCOLS = ["tcp", "udp"];

export function BaselineDialog({
  open,
  initial,
  hosts,
  onClose,
  onCreated,
}: {
  open: boolean;
  initial: BaselineDraft;
  hosts: string[];
  onClose: () => void;
  onCreated: (b: PortBaseline) => void;
}) {
  const L = useLocal({
    ja: {
      title: "ベースラインを追加",
      host: "ホスト",
      hostHint: "空欄 = 全ホスト (*)",
      protocol: "プロトコル",
      port: "ポート",
      portErr: "1〜65535 の整数を入力してください",
      process: "プロセス名",
      processHint: "空欄 = どのプロセスでも許可",
      public: "全インタフェース (0.0.0.0 / ::) での公開を許可",
      publicHint: "オフの場合、全 IF バインドは public_exposure として検知されます",
      note: "メモ",
      save: "追加",
      cancel: "キャンセル",
    },
    en: {
      title: "Add baseline",
      host: "Host",
      hostHint: "Empty = every host (*)",
      protocol: "Protocol",
      port: "Port",
      portErr: "Enter an integer between 1 and 65535",
      process: "Process name",
      processHint: "Empty = any process",
      public: "Allow binding on all interfaces (0.0.0.0 / ::)",
      publicHint: "When off, all-interface binds are flagged as public exposure",
      note: "Note",
      save: "Add",
      cancel: "Cancel",
    },
  });
  const qc = useQueryClient();
  const [d, setD] = useState<BaselineDraft>(initial);
  const [touched, setTouched] = useState(false);
  useEffect(() => {
    if (open) {
      setD(initial);
      setTouched(false);
    }
  }, [open, initial]);

  const port = Number(d.port);
  const portValid = Number.isInteger(port) && port >= 1 && port <= 65535;

  const m = useMutation({
    mutationFn: (body: PortBaselineIn) => api.post<PortBaseline>("/hosts/baselines", body),
    onSuccess: (b) => {
      void qc.invalidateQueries({ queryKey: ["hosts"] });
      onCreated(b);
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setTouched(true);
    if (!portValid) return;
    m.mutate({
      host: d.host.trim() || undefined,
      protocol: d.protocol,
      port,
      process_name: d.process_name.trim() || undefined,
      allow_public: d.allow_public,
      note: d.note.trim() || undefined,
    });
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={L.title}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            {L.cancel}
          </Button>
          <Button type="submit" form="baseline-form" disabled={m.isPending}>
            {L.save}
          </Button>
        </>
      }
    >
      <form id="baseline-form" onSubmit={submit} className="space-y-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_110px_110px]">
          <div>
            <Label htmlFor="bl-host">{L.host}</Label>
            <Input
              id="bl-host"
              value={d.host}
              onChange={(e) => setD({ ...d, host: e.target.value })}
              placeholder="*"
              list="bl-hosts"
            />
            <datalist id="bl-hosts">
              {hosts.map((h) => (
                <option key={h} value={h} />
              ))}
            </datalist>
            <p className="mt-1 text-[11px] text-muted">{L.hostHint}</p>
          </div>
          <div>
            <Label htmlFor="bl-proto">{L.protocol}</Label>
            <Select
              id="bl-proto"
              value={d.protocol}
              onChange={(e) => setD({ ...d, protocol: e.target.value })}
              className="w-full"
            >
              {PROTOCOLS.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="bl-port">{L.port}</Label>
            <Input
              id="bl-port"
              inputMode="numeric"
              value={d.port}
              onChange={(e) => setD({ ...d, port: e.target.value.replace(/[^0-9]/g, "") })}
              aria-invalid={touched && !portValid}
              aria-describedby="bl-port-err"
              className="font-mono"
              required
            />
          </div>
        </div>
        {touched && !portValid && (
          <p id="bl-port-err" className="text-xs text-sev-critical">
            {L.portErr}
          </p>
        )}
        <div>
          <Label htmlFor="bl-proc">{L.process}</Label>
          <Input
            id="bl-proc"
            value={d.process_name}
            onChange={(e) => setD({ ...d, process_name: e.target.value })}
            placeholder="nginx"
            className="font-mono"
          />
          <p className="mt-1 text-[11px] text-muted">{L.processHint}</p>
        </div>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={d.allow_public}
            onChange={(e) => setD({ ...d, allow_public: e.target.checked })}
            className="mt-0.5 h-4 w-4 accent-[var(--tk-accent)]"
          />
          <span>
            {L.public}
            <span className="block text-[11px] text-muted">{L.publicHint}</span>
          </span>
        </label>
        <div>
          <Label htmlFor="bl-note">{L.note}</Label>
          <Textarea
            id="bl-note"
            rows={2}
            value={d.note}
            onChange={(e) => setD({ ...d, note: e.target.value })}
          />
        </div>
        {m.error && <ErrorState error={m.error} />}
      </form>
    </Dialog>
  );
}
