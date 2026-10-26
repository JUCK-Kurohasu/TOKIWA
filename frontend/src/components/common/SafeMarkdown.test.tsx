import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { parseBlocks, SafeMarkdown, safeHref } from "./SafeMarkdown";

function html(md: string): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <SafeMarkdown text={md} />
    </MemoryRouter>,
  );
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
});
