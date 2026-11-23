import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { JsonView } from "./index";
import {
  escapeInvisible,
  escapeJsonInvisible,
  hasInvisible,
  scanInvisible,
  splitInvisible,
} from "./invisible";
import { SafeMarkdown } from "./SafeMarkdown";
import { InvisibleCharsBadge, SafeText } from "./SafeText";

const RLO = "\u202E";
const ZWSP = "\u200B";

describe("invisible / bidi character escaping (#150)", () => {
  it("makes RLO and zero-width characters visible", () => {
    expect(escapeInvisible(`/download/invoice${RLO}fdp.exe`)).toBe("/download/invoice⟨U+202E⟩fdp.exe");
    expect(escapeInvisible(`/.e${ZWSP}nv`)).toBe("/.e⟨U+200B⟩nv");
    expect(escapeInvisible("\uFEFFBOM")).toBe("⟨U+FEFF⟩BOM");
    expect(escapeInvisible("a\u2066b\u2069c")).toBe("a⟨U+2066⟩b⟨U+2069⟩c");
    expect(escapeInvisible("x\u0000y\u001bz")).toBe("x⟨U+0000⟩y⟨U+001B⟩z");
  });

  it("leaves ordinary text alone, including Japanese and emoji", () => {
    for (const s of ["/index.html", "GET /api/v1/users?id=1", "日本語のパス　全角スペース", "🙂 ok"]) {
      expect(hasInvisible(s)).toBe(false);
      expect(escapeInvisible(s)).toBe(s);
    }
  });

  it("keeps TAB / LF / CR only in multi-line mode", () => {
    expect(escapeInvisible("a\tb\nc")).toBe("a⟨U+0009⟩b⟨U+000A⟩c");
    expect(escapeInvisible("a\tb\r\nc", true)).toBe("a\tb\r\nc");
    expect(hasInvisible("line1\nline2", true)).toBe(false);
    expect(escapeInvisible(`body\n${RLO}x`, true)).toBe("body\n⟨U+202E⟩x");
  });

  it("handles astral tag characters and lone surrogates", () => {
    const tag = String.fromCodePoint(0xe0041); // TAG LATIN CAPITAL LETTER A (ASCII smuggling)
    expect(escapeInvisible(`hi${tag}`)).toBe("hi⟨U+E0041⟩");
    expect(escapeInvisible("a\ud800b")).toBe("a⟨U+D800⟩b");
    expect(splitInvisible(`a${RLO}b`)).toEqual(["a", { cp: 0x202e }, "b"]);
  });

  it("escapes flagged characters in raw JSON as \\uXXXX and stays valid JSON", () => {
    const tag = String.fromCodePoint(0xe0041);
    const value = { path: `/invoice${RLO}fdp.exe`, ua: `x${tag}`, plain: "ok" };
    const json = escapeJsonInvisible(JSON.stringify(value));
    expect(json).toContain("\\u202e");
    expect(json).toContain("\\udb40\\udc41");
    expect(json).not.toContain(RLO);
    expect(JSON.parse(json)).toEqual(value);
    const out = renderToStaticMarkup(<JsonView value={value} />);
    expect(out).toContain("\\u202e");
    expect(out).not.toContain(RLO);
  });

  it("scans nested values and reports bidi controls", () => {
    const ev = { http: { path: "/a", headers: { "user-agent": `python ${RLO}7.001` } }, body: "a\nb" };
    expect(scanInvisible(ev)).toEqual({ codePoints: [0x202e], bidi: true });
    expect(scanInvisible({ http: { path: `/.e${ZWSP}nv` } })).toEqual({ codePoints: [0x200b], bidi: false });
    expect(scanInvisible({ body: "line\r\n\tindent" })).toBeNull();
  });

  it("renders visible markers inside unicode-bidi: plaintext and a badge", () => {
    const out = renderToStaticMarkup(<SafeText text={`invoice${RLO}fdp.exe`} />);
    expect(out).toContain("⟨U+202E⟩");
    expect(out).not.toContain(RLO);
    expect(out).toContain("[unicode-bidi:plaintext]");
    expect(out).toContain("RIGHT-TO-LEFT OVERRIDE");
    const badge = renderToStaticMarkup(<InvisibleCharsBadge value={{ path: `/x${RLO}` }} />);
    expect(badge).toContain("不可視/双方向制御文字を含む");
    expect(renderToStaticMarkup(<InvisibleCharsBadge value={{ path: "/x" }} />)).toBe("");
  });

  it("escapes characters in Copilot answers (text and code)", () => {
    const out = renderToStaticMarkup(
      <MemoryRouter>
        <SafeMarkdown
          text={`The path was \`/invoice${RLO}fdp.exe\` and /.e${ZWSP}nv\n\n\`\`\`\n${RLO}x\n\`\`\``}
        />
      </MemoryRouter>,
    );
    expect(out).not.toContain(RLO);
    expect(out).not.toContain(ZWSP);
    expect(out).toContain("⟨U+202E⟩");
    expect(out).toContain("⟨U+200B⟩");
  });
});
