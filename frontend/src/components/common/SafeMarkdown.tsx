/**
 * Tiny, dependency-free Markdown renderer for LLM output (copilot answers).
 *
 * Safety: model text is untrusted. It is parsed into React elements only — never passed to
 * dangerouslySetInnerHTML — so raw HTML in the text is displayed literally. Which links become clickable is
 * decided by `linkPolicy.ts` (audit #144 / #97):
 * - internal links: only known UI routes on the page's own origin (parsed with the URL parser, so backslash
 *   tricks such as "/" + "\" + "evil.example" are rejected); rendered with the router, same tab.
 * - external links: only https hosts on the allowlist; always shown with the real host name next to the label,
 *   with a warning when a URL-shaped label disagrees with the destination. Other external URLs stay plain text
 *   (with their host shown), other schemes (javascript:, data:, vbscript:) stay plain text.
 *
 * Supported: paragraphs, line breaks, # headings, - / * / 1. lists (one nesting level by indent), > quotes,
 * ``` fenced code, `inline code`, **bold**, *italic* / _italic_, [text](url), bare URLs, --- rules, GFM tables.
 */
import { Fragment, type ReactNode } from "react";
import { Link } from "react-router";
import { getLang, type Lang, useLang } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { hasInvisible } from "./invisible";
import { type LinkTarget, labelMismatch, safeHref } from "./linkPolicy";
import { SafeText } from "./SafeText";

export { safeHref };

const URL_RE = /https?:\/\/[^\s<>()"'`]+[^\s<>()"'`.,;:!?]/g;

export interface MarkdownOptions {
  /** "allowlist" (default): only allow-listed https hosts are clickable. "any": every http(s) URL is. */
  externalLinks: "allowlist" | "any";
  lang: Lang;
  /** Internal: true while rendering a link label (no nested autolinks / anchors). */
  inLink?: boolean;
}

const linkStrings = {
  ja: {
    blocked: "リンク無効",
    blockedExternal: "許可リスト外の外部リンクのため、クリックできないようにしています",
    blockedOther: "安全でないリンク先のため、クリックできないようにしています",
    mismatch: "表示とリンク先が異なります",
  },
  en: {
    blocked: "link disabled",
    blockedExternal: "Not clickable: this external host is not on the allowlist",
    blockedOther: "Not clickable: unsafe link target",
    mismatch: "label and destination differ",
  },
};

function defaultOptions(): MarkdownOptions {
  return { externalLinks: "allowlist", lang: getLang() };
}

function HostNote({ host }: { host: string }) {
  return <span className="ml-1 font-mono text-[11px] text-muted">({host})</span>;
}

function renderLink(
  href: string,
  label: ReactNode,
  labelText: string,
  key: string,
  opts: MarkdownOptions,
): ReactNode {
  const S = linkStrings[opts.lang];
  const isBare = labelText === href;
  const safe: LinkTarget | null = safeHref(href);
  if (!safe) {
    if (isBare) return <Fragment key={key}>{label}</Fragment>;
    return (
      <span key={key} title={`${S.blockedOther}: ${href}`}>
        {label}
        <span className="ml-1 text-[11px] text-muted">[{S.blocked}]</span>
      </span>
    );
  }
  const mismatch =
    !isBare && labelMismatch(labelText, safe) ? (
      <span role="note" className="ml-1 text-[11px] font-medium text-sev-high">
        ⚠ {S.mismatch}
      </span>
    ) : null;
  if (safe.kind === "internal") {
    return (
      <Fragment key={key}>
        <Link to={safe.href} className="text-accent underline-offset-2 hover:underline">
          {label}
        </Link>
        {mismatch}
      </Fragment>
    );
  }
  if (!safe.allowed && opts.externalLinks !== "any") {
    return (
      <span key={key} title={`${S.blockedExternal}: ${safe.href}`} className="break-all">
        {label}
        {!isBare && (
          <span className="ml-1 text-[11px] text-muted">
            [<span className="font-mono">{safe.host}</span> — {S.blocked}]
          </span>
        )}
        {mismatch}
      </span>
    );
  }
  return (
    <Fragment key={key}>
      <a
        href={safe.href}
        target="_blank"
        rel="noopener noreferrer nofollow"
        className="break-all text-accent underline-offset-2 hover:underline"
      >
        {label}
      </a>
      {!isBare && <HostNote host={safe.host} />}
      {mismatch}
    </Fragment>
  );
}

/** Text run with invisible / bidi control characters made visible (#150: answers quote attacker data). */
function visible(text: string, key: string, multiline = false): ReactNode {
  return hasInvisible(text, multiline) ? <SafeText key={key} text={text} multiline={multiline} /> : text;
}

/** Plain text with bare URLs turned into links. */
function autolink(text: string, key: string, opts: MarkdownOptions): ReactNode[] {
  if (opts.inLink) return [visible(text, key)];
  const out: ReactNode[] = [];
  let last = 0;
  let n = 0;
  for (const m of text.matchAll(URL_RE)) {
    const idx = m.index ?? 0;
    if (idx > last) out.push(visible(text.slice(last, idx), `${key}-p${n}`));
    out.push(renderLink(m[0], visible(m[0], `${key}-v${n}`), m[0], `${key}-u${n++}`, opts));
    last = idx + m[0].length;
  }
  if (last < text.length) out.push(visible(text.slice(last), `${key}-p${n}`));
  return out;
}

const isWordChar = (c: string | undefined) => !!c && /[\p{L}\p{N}_]/u.test(c);

/** Inline markup → React nodes. */
export function renderInline(text: string, key = "i", opts: MarkdownOptions = defaultOptions()): ReactNode[] {
  const out: ReactNode[] = [];
  let buf = "";
  let n = 0;
  const flush = () => {
    if (buf) {
      out.push(...autolink(buf, `${key}-t${n++}`, opts));
      buf = "";
    }
  };
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    // `code`
    if (ch === "`") {
      const end = text.indexOf("`", i + 1);
      if (end > i + 1) {
        flush();
        out.push(
          <code
            key={`${key}-c${n++}`}
            className="rounded bg-surface-2 px-1 py-0.5 font-mono text-[0.85em] text-fg"
          >
            <SafeText text={text.slice(i + 1, end)} />
          </code>,
        );
        i = end + 1;
        continue;
      }
    }
    // **bold** / __bold__
    if ((ch === "*" || ch === "_") && text[i + 1] === ch) {
      const marker = ch + ch;
      const end = text.indexOf(marker, i + 2);
      if (end > i + 2 && text[i + 2] !== " ") {
        flush();
        out.push(
          <strong key={`${key}-b${n++}`} className="font-semibold text-fg">
            {renderInline(text.slice(i + 2, end), `${key}-b${n}`, opts)}
          </strong>,
        );
        i = end + 2;
        continue;
      }
    }
    // *italic* / _italic_ (underscore only at word boundaries so snake_case stays intact)
    if ((ch === "*" || ch === "_") && text[i + 1] && text[i + 1] !== " " && text[i + 1] !== ch) {
      const okStart = ch === "*" || !isWordChar(text[i - 1]);
      if (okStart) {
        let end = text.indexOf(ch, i + 1);
        while (end > 0 && ch === "_" && isWordChar(text[end + 1])) end = text.indexOf(ch, end + 1);
        if (end > i + 1 && text[end - 1] !== " ") {
          flush();
          out.push(
            <em key={`${key}-e${n++}`}>{renderInline(text.slice(i + 1, end), `${key}-e${n}`, opts)}</em>,
          );
          i = end + 1;
          continue;
        }
      }
    }
    // [label](url)
    if (ch === "[") {
      const m = /^\[([^\]\n]+)\]\(([^)\s]+)\)/.exec(text.slice(i));
      if (m) {
        flush();
        const label = renderInline(m[1], `${key}-l${n}`, { ...opts, inLink: true });
        out.push(renderLink(m[2], label, m[1], `${key}-l${n++}`, opts));
        i += m[0].length;
        continue;
      }
    }
    buf += ch;
    i++;
  }
  flush();
  return out;
}

type Block =
  | { t: "p"; text: string }
  | { t: "h"; level: number; text: string }
  | { t: "code"; lang: string; text: string }
  | { t: "list"; ordered: boolean; items: { text: string; children: string[] }[] }
  | { t: "quote"; text: string }
  | { t: "hr" }
  | { t: "table"; head: string[]; rows: string[][] };

const LIST_RE = /^(\s*)([-*+]|\d{1,3}[.)])\s+(.*)$/;

function splitRow(line: string): string[] {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  return s.split("|").map((c) => c.trim());
}

export function parseBlocks(src: string): Block[] {
  const lines = src.replace(/\r\n?/g, "\n").split("\n");
  const blocks: Block[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    const fence = /^\s*(```|~~~)\s*([\w+-]*)\s*$/.exec(line);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith(fence[1])) body.push(lines[i++]);
      i++; // closing fence (or EOF while streaming)
      blocks.push({ t: "code", lang: fence[2], text: body.join("\n") });
      continue;
    }
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      blocks.push({ t: "h", level: h[1].length, text: h[2].replace(/\s+#+\s*$/, "") });
      i++;
      continue;
    }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) {
      blocks.push({ t: "hr" });
      i++;
      continue;
    }
    if (
      line.includes("|") &&
      i + 1 < lines.length &&
      /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(lines[i + 1])
    ) {
      const head = splitRow(line);
      const rows: string[][] = [];
      i += 2;
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) rows.push(splitRow(lines[i++]));
      blocks.push({ t: "table", head, rows });
      continue;
    }
    if (/^\s*>/.test(line)) {
      const body: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) body.push(lines[i++].replace(/^\s*>\s?/, ""));
      blocks.push({ t: "quote", text: body.join("\n") });
      continue;
    }
    const li = LIST_RE.exec(line);
    if (li) {
      const ordered = /\d/.test(li[2]);
      const baseIndent = li[1].length;
      const items: { text: string; children: string[] }[] = [];
      while (i < lines.length) {
        const m = LIST_RE.exec(lines[i]);
        if (m && m[1].length <= baseIndent + 1) {
          items.push({ text: m[3], children: [] });
          i++;
        } else if (m && items.length) {
          items[items.length - 1].children.push(m[3]);
          i++;
        } else if (lines[i].trim() && /^\s{2,}/.test(lines[i]) && items.length) {
          items[items.length - 1].text += ` ${lines[i].trim()}`;
          i++;
        } else break;
      }
      blocks.push({ t: "list", ordered, items });
      continue;
    }
    const para: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !/^(#{1,6})\s/.test(lines[i]) &&
      !/^\s*(```|~~~)/.test(lines[i]) &&
      !/^\s*>/.test(lines[i]) &&
      !LIST_RE.test(lines[i])
    ) {
      para.push(lines[i++]);
    }
    blocks.push({ t: "p", text: para.join("\n") });
  }
  return blocks;
}

function withBreaks(text: string, key: string, opts: MarkdownOptions): ReactNode[] {
  const parts = text.split("\n");
  return parts.flatMap((part, idx) => {
    const nodes = renderInline(part, `${key}-${idx}`, opts);
    return idx < parts.length - 1 ? [...nodes, <br key={`${key}-br${idx}`} />] : nodes;
  });
}

// Model headings are nested below the page's own headings (h1 page title, h2/h3 cards).
const HEADING_TAGS = ["h3", "h4", "h5", "h6", "h6", "h6"] as const;

const headingClass: Record<number, string> = {
  1: "text-base font-semibold",
  2: "text-[15px] font-semibold",
  3: "text-sm font-semibold",
};

export function SafeMarkdown({
  text,
  className,
  externalLinks = "allowlist",
}: {
  text: string;
  className?: string;
  /** See {@link MarkdownOptions}. Keep the default for anything a model (or telemetry) wrote. */
  externalLinks?: MarkdownOptions["externalLinks"];
}) {
  const { lang } = useLang();
  const opts: MarkdownOptions = { externalLinks, lang };
  const blocks = parseBlocks(text);
  return (
    <div className={cn("space-y-2.5 text-sm leading-relaxed break-words", className)}>
      {blocks.map((b, bi) => {
        const k = `b${bi}`;
        switch (b.t) {
          case "h": {
            const H = HEADING_TAGS[Math.min(b.level, HEADING_TAGS.length) - 1];
            return (
              <H key={k} className={headingClass[b.level] ?? "text-sm font-semibold"}>
                {renderInline(b.text, k, opts)}
              </H>
            );
          }
          case "code":
            return (
              <pre
                key={k}
                className="overflow-x-auto rounded-md border border-line bg-bg p-3 font-mono text-xs leading-relaxed"
              >
                {b.lang && (
                  <div className="mb-1 text-[10px] uppercase tracking-wider text-muted">{b.lang}</div>
                )}
                <code>
                  <SafeText text={b.text} multiline />
                </code>
              </pre>
            );
          case "list": {
            const Tag = b.ordered ? "ol" : "ul";
            return (
              <Tag key={k} className={cn("space-y-1 pl-5", b.ordered ? "list-decimal" : "list-disc")}>
                {b.items.map((it, ii) => (
                  <li key={`${k}-${ii}`}>
                    {renderInline(it.text, `${k}-${ii}`, opts)}
                    {it.children.length > 0 && (
                      <ul className="mt-1 list-[circle] space-y-1 pl-5">
                        {it.children.map((c, ci) => (
                          <li key={`${k}-${ii}-${ci}`}>{renderInline(c, `${k}-${ii}-${ci}`, opts)}</li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
              </Tag>
            );
          }
          case "quote":
            return (
              <blockquote key={k} className="border-l-2 border-line pl-3 text-muted">
                {withBreaks(b.text, k, opts)}
              </blockquote>
            );
          case "hr":
            return <hr key={k} className="border-line" />;
          case "table":
            return (
              <div key={k} className="overflow-x-auto rounded-md border border-line">
                <table className="w-full border-collapse text-xs">
                  <thead className="bg-surface-2 text-left text-muted">
                    <tr>
                      {b.head.map((c, ci) => (
                        <th key={ci} className="px-2 py-1.5 font-medium">
                          {renderInline(c, `${k}-h${ci}`, opts)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {b.rows.map((r, ri) => (
                      <tr key={ri}>
                        {b.head.map((_, ci) => (
                          <td key={ci} className="px-2 py-1.5 align-top">
                            {renderInline(r[ci] ?? "", `${k}-${ri}-${ci}`, opts)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          default:
            return <p key={k}>{withBreaks(b.text, k, opts)}</p>;
        }
      })}
    </div>
  );
}
