/**
 * Localized enum labels and small helpers shared by the ops pages (alerts / incidents / response / deception).
 * Labels are {ja, en} objects; render them with `useLabel()` from @/lib/i18n.
 */
import { useEffect, useState } from "react";
import type {
  ActionStatus,
  ActionType,
  AlertCategory,
  AlertStatus,
  AttackStage,
  DeceptionKind,
  IncidentStatus,
} from "@/api/types";
import type { ActionProposer } from "@/api/types-ops";
import { getLang } from "@/lib/i18n";
import { useAuth } from "@/stores/auth";

export type Localized = { ja: string; en: string };

export const alertStatusLabel: Record<AlertStatus, Localized> = {
  new: { ja: "新規", en: "New" },
  triaging: { ja: "トリアージ中", en: "Triaging" },
  triaged: { ja: "トリアージ済", en: "Triaged" },
  acknowledged: { ja: "確認済", en: "Acknowledged" },
  resolved: { ja: "解決", en: "Resolved" },
  false_positive: { ja: "誤検知", en: "False positive" },
};

export const alertCategoryLabel: Record<AlertCategory, Localized> = {
  recon: { ja: "偵察", en: "Recon" },
  scan: { ja: "スキャン", en: "Scan" },
  exploit_attempt: { ja: "攻撃試行", en: "Exploit attempt" },
  credential_attack: { ja: "認証攻撃", en: "Credential attack" },
  ai_agent: { ja: "AIエージェント", en: "AI agent" },
  prompt_injection: { ja: "プロンプトインジェクション", en: "Prompt injection" },
  deception: { ja: "デセプション", en: "Deception" },
  port_deviation: { ja: "ポート逸脱", en: "Port deviation" },
  policy: { ja: "ポリシー", en: "Policy" },
  vuln_exposure: { ja: "脆弱性露出", en: "Vuln exposure" },
  ids: { ja: "IDS", en: "IDS" },
  anomaly: { ja: "異常", en: "Anomaly" },
  other: { ja: "その他", en: "Other" },
};

/** Categories that are about AI (rendered in purple). */
export const AI_CATEGORIES: ReadonlySet<string> = new Set(["ai_agent", "prompt_injection"]);

export const incidentStatusLabel: Record<IncidentStatus, Localized> = {
  open: { ja: "オープン", en: "Open" },
  investigating: { ja: "調査中", en: "Investigating" },
  contained: { ja: "封じ込め済", en: "Contained" },
  resolved: { ja: "解決", en: "Resolved" },
  false_positive: { ja: "誤検知", en: "False positive" },
};

export const actionTypeLabel: Record<ActionType, Localized> = {
  block_ip: { ja: "IP 遮断", en: "Block IP" },
  rate_limit: { ja: "レート制限", en: "Rate limit" },
  tarpit: { ja: "ターピット（遅延）", en: "Tarpit" },
  deceive: { ja: "デコイへ誘導", en: "Divert to decoys" },
  deploy_canary: { ja: "カナリア追加", en: "Deploy canary" },
  notify: { ja: "通知", en: "Notify" },
  webhook: { ja: "Webhook 連携", en: "Webhook" },
  nftables_block: { ja: "nftables 遮断", en: "nftables block" },
};

/** What the executor will do once a human approves (shown in the approval dialog). */
export const actionTypeEffect: Record<ActionType, Localized> = {
  block_ip: {
    ja: "TOKIWA Gate がこの送信元からのリクエストを 403 で拒否します。",
    en: "TOKIWA Gate rejects requests from this source with 403.",
  },
  rate_limit: {
    ja: "TOKIWA Gate がこの送信元の毎分リクエスト数を制限します。",
    en: "TOKIWA Gate limits requests per minute from this source.",
  },
  tarpit: {
    ja: "TOKIWA Gate がこの送信元への応答に遅延を加え、攻撃を遅らせます。",
    en: "TOKIWA Gate adds latency to responses for this source.",
  },
  deceive: {
    ja: "この送信元からのリクエストをすべて Mirage のデコイで応答します（本番には届きません）。",
    en: "Every request from this source is answered from Mirage decoys (never reaches upstream).",
  },
  deploy_canary: {
    ja: "ハニートークン / AI カナリアを自組織の資産上に追加で配置します。",
    en: "Plants an additional honeytoken / AI canary on your own assets.",
  },
  notify: {
    ja: "通知チャネルで担当者を呼び出します。",
    en: "Pages a human via the notification channels.",
  },
  webhook: {
    ja: "外部の SOAR / ファイアウォールへ Webhook で引き渡します。",
    en: "Hands off to an external SOAR / firewall via webhook.",
  },
  nftables_block: {
    ja: "ホストのファイアウォールに固定テンプレートで遮断ルールを追加します（サーバー設定で無効な場合は失敗します）。",
    en: "Adds a host firewall drop rule from a fixed template (fails when disabled in server settings).",
  },
};

export const actionStatusLabel: Record<ActionStatus, Localized> = {
  proposed: { ja: "承認待ち", en: "Awaiting approval" },
  approved: { ja: "承認済（実行待ち）", en: "Approved (pending)" },
  active: { ja: "実行中", en: "Active" },
  expired: { ja: "期限切れ", en: "Expired" },
  reverted: { ja: "取り消し済", en: "Reverted" },
  rejected: { ja: "却下", en: "Rejected" },
  failed: { ja: "失敗", en: "Failed" },
};

export const proposerLabel: Record<ActionProposer, Localized> = {
  rule: { ja: "ルール提案", en: "Rule" },
  llm: { ja: "LLM 提案", en: "LLM" },
  user: { ja: "ユーザー提案", en: "User" },
  policy: { ja: "ポリシー", en: "Policy" },
};

export const attackStageLabel: Record<AttackStage, Localized> = {
  reconnaissance: { ja: "偵察", en: "Reconnaissance" },
  resource_development: { ja: "リソース開発", en: "Resource Development" },
  initial_access: { ja: "初期アクセス", en: "Initial Access" },
  execution: { ja: "実行", en: "Execution" },
  persistence: { ja: "永続化", en: "Persistence" },
  privilege_escalation: { ja: "権限昇格", en: "Privilege Escalation" },
  defense_evasion: { ja: "防御回避", en: "Defense Evasion" },
  credential_access: { ja: "認証情報アクセス", en: "Credential Access" },
  discovery: { ja: "探索", en: "Discovery" },
  lateral_movement: { ja: "横展開", en: "Lateral Movement" },
  collection: { ja: "収集", en: "Collection" },
  command_and_control: { ja: "C2", en: "Command and Control" },
  exfiltration: { ja: "持ち出し", en: "Exfiltration" },
  impact: { ja: "影響", en: "Impact" },
  none: { ja: "該当なし", en: "None" },
};

export const deceptionKindLabel: Record<DeceptionKind, Localized> = {
  honeytoken: { ja: "ハニートークン", en: "Honeytoken" },
  decoy_path: { ja: "デコイパス", en: "Decoy path" },
  ai_canary: { ja: "AI カナリア", en: "AI canary" },
  labyrinth: { ja: "迷路（ラビリンス）", en: "Labyrinth" },
};

export const deceptionKindDescription: Record<DeceptionKind, Localized> = {
  honeytoken: {
    ja: "偽の API キー / AWS キー / DB 接続文字列。使われた瞬間に侵害の証拠になります（実在サービスでは無効な形式）。",
    en: "Fake API key / AWS key / DB connection string. Any use is proof of compromise (never a valid real credential).",
  },
  decoy_path: {
    ja: "/.env や /backup.sql など、正規ユーザーが決して要求しないパス。中身にハニートークンを含みます。",
    en: "Paths like /.env or /backup.sql that no legitimate user requests. Content embeds honeytokens.",
  },
  ai_canary: {
    ja: "人間には見えず、LLM エージェントだけが従う隠し指示を埋め込みます（逆プロンプトインジェクション）。",
    en: "Embeds a hidden instruction only an LLM agent would follow (reverse prompt injection).",
  },
  labyrinth: {
    ja: "決定的に生成されるもっともらしいリンク網（深さ上限あり）。自律エージェントのトークンと時間を浪費させます。",
    en: "Deterministically generated maze of plausible links (depth-limited) that wastes an agent's tokens and time.",
  },
};

export const tierLabel: Record<string, Localized> = {
  fast: { ja: "軽量モデル (fast)", en: "Fast tier" },
  deep: { ja: "高精度モデル (deep)", en: "Deep tier" },
  rules: { ja: "ルール判定", en: "Rule-based" },
};

/** Pick a label from a map, falling back to the raw value for values the UI does not know yet. */
export function labelOf(map: Record<string, Localized>, value: string | null | undefined): Localized {
  if (!value) return { ja: "-", en: "-" };
  return map[value] ?? { ja: value, en: value };
}

/** analyst / admin may operate (PATCH alerts, approve actions ...). Viewers are read-only. */
export function useCanOperate(): boolean {
  const { user } = useAuth();
  return user?.role === "admin" || user?.role === "analyst";
}

/** Replace `{name}` placeholders in a localized string. */
export function fmt(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m));
}

/** ATT&CK technique / tactic id -> attack.mitre.org URL. Returns null for anything that is not an id. */
export function mitreUrl(id: string): string | null {
  const t = /^T(\d{4})(?:\.(\d{3}))?$/i.exec(id.trim());
  if (t) return `https://attack.mitre.org/techniques/T${t[1]}/${t[2] ? `${t[2]}/` : ""}`;
  const ta = /^TA(\d{4})$/i.exec(id.trim());
  if (ta) return `https://attack.mitre.org/tactics/TA${ta[1]}/`;
  return null;
}

/** Re-render periodically (countdowns / "x minutes left"). */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}

/** "1時間12分" / "1h 12m" style duration. */
export function formatDuration(ms: number): string {
  const ja = getLang() === "ja";
  const totalMin = Math.max(0, Math.round(ms / 60_000));
  const d = Math.floor(totalMin / 1440);
  const h = Math.floor((totalMin % 1440) / 60);
  const m = totalMin % 60;
  if (ja) {
    if (d) return `${d}日${h ? `${h}時間` : ""}`;
    if (h) return `${h}時間${m ? `${m}分` : ""}`;
    return `${m}分`;
  }
  if (d) return `${d}d${h ? ` ${h}h` : ""}`;
  if (h) return `${h}h${m ? ` ${m}m` : ""}`;
  return `${m}m`;
}

export function formatTtl(minutes: number | null | undefined): string {
  if (minutes == null) return "-";
  return formatDuration(minutes * 60_000);
}
