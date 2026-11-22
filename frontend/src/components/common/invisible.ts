/**
 * Invisible / bidirectional control characters in attacker-controlled telemetry (audit #150, Trojan Source).
 *
 * React escapes HTML, but it still hands U+202E (RIGHT-TO-LEFT OVERRIDE), zero-width characters and other
 * control/format code points to the browser, which reorders or hides them: `/download/invoice\u202Efdp.exe`
 * is displayed as "invoiceexe.pdf", `/.e\u200Bnv` looks exactly like "/.env". These helpers make such code
 * points visible as `⟨U+202E⟩` at display time only — filters, searches and copy-to-filter keep the raw value.
 *
 * Flagged: Unicode general categories Cc (controls), Cf (format: bidi controls, zero-width, BOM, soft hyphen,
 * tag characters), Cs (lone surrogates), Zl/Zp (line/paragraph separators), plus the Hangul filler letters that
 * render as blank. In multi-line mode TAB / LF / CR are kept (request bodies, prompts).
 *
 * Where to adjust: {@link FLAG_RE} (what is flagged) and {@link CHAR_NAMES} (tooltip names).
 */

/** Code points that are flagged. Keep FLAG_RE and FLAG_RE_G identical. */
export const FLAG_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\u115F\u1160\u3164\uFFA0]/u;
const FLAG_RE_G = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\u115F\u1160\u3164\uFFA0]/gu;
/** Characters that reorder text (the Trojan Source set). */
export const BIDI_RE = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/u;

const MULTILINE_OK = new Set([0x09, 0x0a, 0x0d]);

export const CHAR_NAMES: Readonly<Record<number, string>> = {
  0: "NULL",
  9: "CHARACTER TABULATION",
  10: "LINE FEED",
  13: "CARRIAGE RETURN",
  27: "ESCAPE",
  127: "DELETE",
  173: "SOFT HYPHEN",
  1564: "ARABIC LETTER MARK",
  4447: "HANGUL CHOSEONG FILLER",
  4448: "HANGUL JUNGSEONG FILLER",
  6158: "MONGOLIAN VOWEL SEPARATOR",
  8203: "ZERO WIDTH SPACE",
  8204: "ZERO WIDTH NON-JOINER",
  8205: "ZERO WIDTH JOINER",
  8206: "LEFT-TO-RIGHT MARK",
  8207: "RIGHT-TO-LEFT MARK",
  8232: "LINE SEPARATOR",
  8233: "PARAGRAPH SEPARATOR",
  8234: "LEFT-TO-RIGHT EMBEDDING",
  8235: "RIGHT-TO-LEFT EMBEDDING",
  8236: "POP DIRECTIONAL FORMATTING",
  8237: "LEFT-TO-RIGHT OVERRIDE",
  8238: "RIGHT-TO-LEFT OVERRIDE",
  8288: "WORD JOINER",
  8294: "LEFT-TO-RIGHT ISOLATE",
  8295: "RIGHT-TO-LEFT ISOLATE",
  8296: "FIRST STRONG ISOLATE",
  8297: "POP DIRECTIONAL ISOLATE",
  12644: "HANGUL FILLER",
  65279: "ZERO WIDTH NO-BREAK SPACE (BOM)",
  65440: "HALFWIDTH HANGUL FILLER",
};

export function codePointLabel(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

export function charTitle(cp: number): string {
  const name = CHAR_NAMES[cp] ?? (cp >= 0xe0000 && cp <= 0xe007f ? "TAG CHARACTER" : undefined);
  return name ? `${codePointLabel(cp)} ${name}` : codePointLabel(cp);
}

function flagged(ch: string, multiline: boolean): boolean {
  if (!FLAG_RE.test(ch)) return false;
  return !(multiline && MULTILINE_OK.has(ch.codePointAt(0) ?? -1));
}

/** Fast check (no allocation) whether a string contains anything that would be escaped. */
export function hasInvisible(s: string | null | undefined, multiline = false): boolean {
  if (!s || !FLAG_RE.test(s)) return false;
  if (!multiline) return true;
  FLAG_RE_G.lastIndex = 0;
  for (const m of s.matchAll(FLAG_RE_G)) if (!MULTILINE_OK.has(m[0].codePointAt(0) ?? -1)) return true;
  return false;
}

export type InvisiblePart = string | { cp: number };

/** Split into plain runs and flagged code points (for rendering). */
export function splitInvisible(s: string, multiline = false): InvisiblePart[] {
  if (!hasInvisible(s, multiline)) return [s];
  const out: InvisiblePart[] = [];
  let buf = "";
  for (const ch of s) {
    if (flagged(ch, multiline)) {
      if (buf) out.push(buf);
      buf = "";
      out.push({ cp: ch.codePointAt(0) ?? 0 });
    } else buf += ch;
  }
  if (buf) out.push(buf);
  return out;
}

/** String form for places that cannot hold markup (title attributes, drawer titles, compact summaries). */
export function escapeInvisible(s: string | null | undefined, multiline = false): string {
  if (s == null) return "";
  if (!hasInvisible(s, multiline)) return s;
  return splitInvisible(s, multiline)
    .map((p) => (typeof p === "string" ? p : `⟨${codePointLabel(p.cp)}⟩`))
    .join("");
}

/**
 * JSON text with every flagged character written as a `\uXXXX` escape (astral code points as surrogate
 * pairs), so the raw view stays valid, exact JSON and nothing is hidden. Only meant for JSON.stringify output,
 * where flagged characters can only occur inside string literals.
 */
export function escapeJsonInvisible(json: string): string {
  if (!FLAG_RE.test(json)) return json;
  FLAG_RE_G.lastIndex = 0;
  return json.replace(FLAG_RE_G, (ch) => {
    let out = "";
    for (let i = 0; i < ch.length; i++) out += `\\u${ch.charCodeAt(i).toString(16).padStart(4, "0")}`;
    return out;
  });
}

export interface InvisibleScan {
  /** Flagged code points found (deduplicated, in order of appearance, at most 20). */
  codePoints: number[];
  /** At least one bidi control (reorders the display). */
  bidi: boolean;
}

/**
 * Walk every string in a value (event, tool result …). TAB / LF / CR are not reported (bodies, prompts).
 * Bounded so a huge event cannot stall the UI.
 */
export function scanInvisible(value: unknown, maxStrings = 2000): InvisibleScan | null {
  const seen = new Set<number>();
  let bidi = false;
  let budget = maxStrings;
  const visit = (v: unknown, depth: number): void => {
    if (budget <= 0 || depth > 8 || v == null) return;
    if (typeof v === "string") {
      budget--;
      if (!hasInvisible(v, true)) return;
      for (const p of splitInvisible(v, true)) {
        if (typeof p !== "string" && seen.size < 20) seen.add(p.cp);
      }
      if (BIDI_RE.test(v)) bidi = true;
      return;
    }
    if (Array.isArray(v)) {
      for (const x of v) visit(x, depth + 1);
      return;
    }
    if (typeof v === "object") {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        visit(k, depth + 1);
        visit(x, depth + 1);
      }
    }
  };
  visit(value, 0);
  return seen.size ? { codePoints: [...seen], bidi } : null;
}
