import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { appRoutes } from "@/routes";
import { INTERNAL_LINK_PREFIXES, labelHost, labelMismatch } from "./linkPolicy";
import { parseBlocks, SafeMarkdown, safeHref } from "./SafeMarkdown";

function html(md: string, externalLinks?: "allowlist" | "any"): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <SafeMarkdown text={md} externalLinks={externalLinks} />
    </MemoryRouter>,
  );
}

/** href values of every rendered <a>. */
function hrefs(out: string): string[] {
  return [...out.matchAll(/<a [^>]*href="([^"]*)"/g)].map((m) => m[1]);
}

describe("SafeMarkdown", () => {
  it("escapes raw HTML from the model", () => {
    const out = html('<script>alert(1)</script> <img src=x onerror="alert(2)">');
    expect(out).not.toContain("<script>");
    expect(out).not.toContain("<img");
    expect(out).toContain("&lt;script&gt;");
  });

  it("does not render javascript:/data: links", () => {
    const out = html("[click](javascript:alert(1)) [d](data:text/html,x)");
    expect(out).not.toContain("href=");
    expect(safeHref("javascript:alert(1)")).toBeNull();
    expect(safeHref("//evil.example/x")).toBeNull();
  });

  it("renders http(s) links with noopener and internal paths", () => {
    const out = html("see [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-0001) and [alert](/alerts/abc)");
    expect(out).toContain('href="https://nvd.nist.gov/vuln/detail/CVE-2024-0001"');
    expect(out).toContain('rel="noopener noreferrer nofollow"');
    expect(out).toContain('href="/alerts/abc"');
  });

  it("parses code, lists, headings and tables", () => {
    const blocks = parseBlocks(
      "# Title\n\n- a\n- b\n\n```sql\nSELECT 1\n```\n\n| k | v |\n|---|---|\n| x | y |",
    );
    expect(blocks.map((b) => b.t)).toEqual(["h", "list", "code", "table"]);
    const out = html("**bold** `search_events` keeps snake_case_names intact");
    expect(out).toContain("<strong");
    expect(out).toContain("<code");
    expect(out).toContain("snake_case_names");
    expect(out).not.toContain("<em>");
  });

  it("autolinks bare URLs without trailing punctuation", () => {
    const out = html("Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog.");
    expect(out).toContain('href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"');
  });

  // ---- #144: internal-link spoofing via the URL parser's backslash / tab handling
  it("never treats backslash / tab / protocol-relative tricks as internal", () => {
    const tricks = [
      "/\\x.example",
      "/\\/x.example",
      "/\t/x.example",
      "\\\\x.example",
      "/\\attacker.invalid/approve?d=SUMMARY",
      "//x.example",
      "/\n/x.example",
      "/ /x.example",
      "/‮/x.example",
      "/​/alerts",
    ];
    for (const t of tricks) {
      const r = safeHref(t);
      expect(r?.internal ?? false, JSON.stringify(t)).toBe(false);
    }
  });

  it("does not render a same-tab link for /\\host markdown links", () => {
    const out = html("[TOKIWA 承認画面で確認](/\\attacker.invalid/approve?d=SUMMARY) and [x](/\\/x.example)");
    expect(hrefs(out)).toEqual([]);
    expect(out).toContain("TOKIWA 承認画面で確認");
  });

  it("limits internal links to known UI routes and navigates to the parsed path", () => {
    expect(safeHref("/alerts/abc")).toEqual({ kind: "internal", internal: true, href: "/alerts/abc" });
    expect(safeHref("/incidents/01x?tab=a#b")?.href).toBe("/incidents/01x?tab=a#b");
    expect(safeHref("/")?.internal).toBe(true);
    expect(safeHref("/alerts/../events")?.href).toBe("/events");
    expect(safeHref("/login")).toBeNull();
    expect(safeHref("/setup")).toBeNull();
    expect(safeHref("/api/v1/auth/logout")).toBeNull();
    expect(safeHref("/alertsX")).toBeNull();
    expect(safeHref("/%5Cx.example")).toBeNull();
  });

  it("every internal link prefix is a real UI route", () => {
    const paths = new Set(appRoutes.map((r) => r.path));
    for (const p of INTERNAL_LINK_PREFIXES) expect(paths.has(p), p).toBe(true);
  });

  // ---- #97: external links
  it("keeps non-allowlisted external links as plain text with the real host shown", () => {
    const out = html("[インシデント詳細を開く](https://attacker.example/?d=secret-summary)");
    expect(hrefs(out)).toEqual([]);
    expect(out).toContain("インシデント詳細を開く");
    expect(out).toContain("attacker.example");
    const bare = html("see https://attacker.example/x?d=1 now");
    expect(hrefs(bare)).toEqual([]);
    expect(bare).toContain("https://attacker.example/x?d=1");
  });

  it("allows only https links to allowlisted hosts without credentials or ports", () => {
    expect(safeHref("https://nvd.nist.gov/vuln/detail/CVE-2024-0001")).toMatchObject({ allowed: true });
    expect(safeHref("https://www.cisa.gov/kev")).toMatchObject({ allowed: true, host: "www.cisa.gov" });
    expect(safeHref("http://nvd.nist.gov/x")).toMatchObject({ allowed: false });
    expect(safeHref("https://nvd.nist.gov.attacker.example/x")).toMatchObject({ allowed: false });
    expect(safeHref("https://attacker-nvd.nist.gov.example/x")).toMatchObject({ allowed: false });
    expect(safeHref("https://nvd.nist.gov@attacker.example/x")).toMatchObject({
      allowed: false,
      host: "attacker.example",
    });
    expect(safeHref("https://nvd.nist.gov:8443/x")).toMatchObject({ allowed: false });
    // IDN look-alike (Cyrillic і): shown in punycode and not allowed.
    const idn = safeHref("https://nvd.nіst.gov/x");
    expect(idn).toMatchObject({ allowed: false });
    expect(idn && !idn.internal ? idn.host : "").toMatch(/xn--/);
  });

  it("shows the real host next to an allowed link's label", () => {
    const out = html("[NVD のページ](https://nvd.nist.gov/vuln/detail/CVE-2024-0001)");
    expect(hrefs(out)).toEqual(["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"]);
    expect(out).toContain("(nvd.nist.gov)");
  });

  it("warns when a URL-shaped label disagrees with the destination", () => {
    expect(labelHost("https://nvd.nist.gov/x")).toBe("nvd.nist.gov");
    expect(labelHost("**nvd.nist.gov**")).toBe("nvd.nist.gov");
    expect(labelHost("インシデント詳細")).toBeNull();
    const t = safeHref("https://attack.mitre.org/techniques/T1190/");
    expect(t && labelMismatch("https://nvd.nist.gov/vuln/detail/CVE-1", t)).toBe(true);
    expect(t && labelMismatch("attack.mitre.org/techniques/T1190", t)).toBe(false);
    const out = html("[https://nvd.nist.gov/vuln](https://attack.mitre.org/techniques/T1190/)");
    expect(hrefs(out)).toEqual(["https://attack.mitre.org/techniques/T1190/"]); // no nested autolink
    expect(out).toContain('role="note"');
    const spoof = html("[https://nvd.nist.gov/x](https://attacker.example/?d=1)");
    expect(hrefs(spoof)).toEqual([]);
    expect(spoof).toContain('role="note"');
  });

  it("externalLinks=any keeps every http(s) link clickable (trusted sources only)", () => {
    const out = html("[vendor](https://vendor.example/advisory)", "any");
    expect(hrefs(out)).toEqual(["https://vendor.example/advisory"]);
    expect(out).toContain("(vendor.example)");
  });
});
