/**
 * Preview of what a Mirage asset actually serves (GET /deception/preview/{id}).
 * The body is shown as text — never rendered as HTML — with the canary token highlighted.
 */
import { useQuery } from "@tanstack/react-query";
import { Bot, Eye } from "lucide-react";
import { Fragment } from "react";
import { api } from "@/api/client";
import type { DeceptionAsset } from "@/api/types";
import type { DeceptionPreview } from "@/api/types-ops";
import { Notice } from "@/components/common/OpsKit";
import { fmt } from "@/components/common/opsLabels";
import { Button, Dialog, ErrorState, Skeleton } from "@/components/ui";
import { useLocal } from "@/lib/i18n";
import { KindTag } from "./kinds";

const strings = {
  ja: {
    title: "プレビュー: {name}",
    path: "パス",
    type: "Content-Type",
    size: "{n} 文字",
    textOnly: "本文はテキストとして表示しています（HTML はレンダリングしません）。紫の強調はカナリア値です。",
    aiNote:
      "隠し指示はブラウザでは見えません（HTML コメント・不可視要素など）が、HTML をそのまま読む LLM エージェントには届きます。",
    tokenHits: "カナリア値の出現: {n} 箇所",
    empty: "本文は空です",
    close: "閉じる",
  },
  en: {
    title: "Preview: {name}",
    path: "Path",
    type: "Content-Type",
    size: "{n} chars",
    textOnly: "The body is shown as text (HTML is not rendered). Purple highlights mark the canary value.",
    aiNote:
      "Browsers never display the hidden instruction (HTML comment, invisible element …), but an LLM agent reading the raw HTML does.",
    tokenHits: "Canary value occurrences: {n}",
    empty: "The body is empty",
    close: "Close",
  },
};

function Highlighted({ body, token }: { body: string; token: string | null }) {
  if (!token || token.length < 4 || !body.includes(token)) return <>{body}</>;
  const parts = body.split(token);
  return (
    <>
      {parts.map((part, i) => (
        <Fragment key={i}>
          {part}
          {i < parts.length - 1 && <mark className="rounded-sm bg-ai/30 px-0.5 text-ai">{token}</mark>}
        </Fragment>
      ))}
    </>
  );
}

export function PreviewDialog({ asset, onClose }: { asset: DeceptionAsset | null; onClose: () => void }) {
  const L = useLocal(strings);
  const q = useQuery({
    queryKey: ["deception", "preview", asset?.id],
    queryFn: () => api.get<DeceptionPreview>(`/deception/preview/${encodeURIComponent(asset?.id ?? "")}`),
    enabled: !!asset,
    staleTime: 0,
  });
  const data = q.data;
  const hits = data && asset?.token ? data.body.split(asset.token).length - 1 : 0;

  return (
    <Dialog
      open={!!asset}
      onClose={onClose}
      wide
      title={
        <span className="flex items-center gap-2">
          <Eye className="h-4 w-4 text-accent" aria-hidden />
          {fmt(L.title, { name: asset?.name ?? "" })}
        </span>
      }
      footer={<Button onClick={onClose}>{L.close}</Button>}
    >
      {asset && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
            <KindTag kind={asset.kind} />
            {data && (
              <>
                <span>
                  <span className="text-muted">{L.path}: </span>
                  <span className="font-mono">{data.path}</span>
                </span>
                <span>
                  <span className="text-muted">{L.type}: </span>
                  <span className="font-mono">{data.content_type}</span>
                </span>
                <span className="text-muted">{fmt(L.size, { n: data.body.length })}</span>
                {asset.token && <span className="text-ai">{fmt(L.tokenHits, { n: hits })}</span>}
              </>
            )}
          </div>
          {asset.kind === "ai_canary" && (
            <Notice tone="ai" icon={<Bot className="h-4 w-4 text-ai" aria-hidden />}>
              {L.aiNote}
            </Notice>
          )}
          {q.isLoading ? (
            <Skeleton className="h-64" />
          ) : q.error ? (
            <ErrorState error={q.error} />
          ) : data ? (
            data.body ? (
              <pre className="max-h-[55vh] overflow-auto whitespace-pre-wrap break-all rounded-md border border-line bg-bg p-3 font-mono text-xs leading-relaxed">
                <Highlighted body={data.body} token={asset.token} />
              </pre>
            ) : (
              <p className="text-sm text-muted">{L.empty}</p>
            )
          ) : null}
          <p className="text-[11px] text-muted">{L.textOnly}</p>
        </div>
      )}
    </Dialog>
  );
}
