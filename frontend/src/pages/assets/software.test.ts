import { describe, expect, it } from "vitest";
import { looksLikeCpe, parseBulk, parseCpe23, toItems } from "./software";

describe("software inventory helpers", () => {
  it("parses pip, npm, whitespace and CPE lines", () => {
    const rows = parseBulk(
      "django==4.2.7\n@scope/pkg@1.2.3\nopenssl 3.0.13\n# comment\n\ncpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*\nredis",
      "PyPI",
    );
    expect(rows.map((r) => [r.product, r.version])).toEqual([
      ["django", "4.2.7"],
      ["@scope/pkg", "1.2.3"],
      ["openssl", "3.0.13"],
      ["nginx", "1.24.0"],
      ["redis", ""],
    ]);
    expect(rows[3].vendor).toBe("nginx");
    expect(rows[3].cpe).toMatch(/^cpe:2\.3:a:nginx/);
    expect(rows[0].ecosystem).toBe("PyPI");
  });

  it("converts rows to SoftwareItem with nulls and drops blank rows", () => {
    const items = toItems([
      { key: "a", vendor: "", product: " nginx ", version: "1.24", cpe: "", ecosystem: "" },
      { key: "b", vendor: "", product: "", version: "", cpe: "", ecosystem: "" },
    ]);
    expect(items).toEqual([{ vendor: null, product: "nginx", version: "1.24", cpe: null, ecosystem: null }]);
  });

  it("recognizes CPE formats", () => {
    expect(looksLikeCpe("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*")).toBe(true);
    expect(looksLikeCpe("apache httpd")).toBe(false);
    expect(parseCpe23("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")).toEqual({
      vendor: "apache",
      product: "http_server",
      version: undefined,
    });
  });
});
