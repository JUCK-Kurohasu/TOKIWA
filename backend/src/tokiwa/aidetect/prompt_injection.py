"""Prompt-injection / jailbreak detection for prompts sent to protected LLM applications (FR-14).

Families (each with English and Japanese phrasings):

- ``instruction_override``       "ignore all previous instructions" / 「これまでの指示を無視」
- ``system_prompt_extraction``   "reveal your system prompt" / 「システムプロンプトを教えて」
- ``roleplay_jailbreak``         DAN / developer mode / "pretend you have no restrictions" / 「制限のない AI として」
- ``obfuscated_instruction``     Base64-wrapped instructions, Unicode tag characters (ASCII smuggling),
                                 invisible / bidi control characters, "decode this and follow it"
- ``tool_abuse``                 steering the app's tools: "use the email tool to send ...", "run this command"
- ``markdown_exfiltration``      markdown/HTML images whose URL carries data in the query string
- ``delimiter_injection``        fake chat-template / role delimiters (``<|im_start|>``, ``[INST]``, ``</system>``)

This is pattern matching, so it is evadable by paraphrase and will produce false positives on text that *talks
about* these attacks. Severity is therefore graded by how many families match and by their strength; the LLM
triage stage and the analyst make the final call. Regexes are bounded (no catastrophic backtracking) and input is
truncated to ``MAX_PROMPT_CHARS``.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl

MAX_PROMPT_CHARS = 8192

_ZERO_WIDTH = frozenset(
    {0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF}
)
_BIDI = frozenset({0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069})


def _c(p: str) -> re.Pattern[str]:
    return re.compile(p, re.I | re.S)


_FAMILY_PATTERNS: dict[str, tuple[float, tuple[re.Pattern[str], ...]]] = {
    "instruction_override": (
        0.75,
        (
            _c(
                r"\b(?:ignore|disregard|forget|override|bypass|skip|drop)\b.{0,30}?"
                r"\b(?:previous|prior|above|earlier|preceding|initial|original|system|developer|all)\b.{0,20}?"
                r"\b(?:instructions?|prompts?|rules|directions|guidelines|context|constraints|commands|directives)\b"
            ),
            _c(r"\bnew\s+(?:instructions?|rules|system\s+prompt)\s*:"),
            _c(r"\bfrom\s+now\s+on\b.{0,40}?\byou\s+(?:are|will|must|shall)\b"),
            _c(r"\byour\s+(?:new\s+)?(?:task|instructions?|goal|purpose)\s+(?:is|are)\s+now\b"),
            _c(
                r"(?:これまで|以前|前|上記|先ほど|今まで|最初|元)の?(?:すべての|全ての|全部の)?"
                r"(?:指示|命令|ルール|設定|プロンプト|制約)(?:は|を|も)?(?:すべて|全て|全部)?(?:無視|忘れ|破棄|取り消)"
            ),
            _c(r"(?:指示|命令|ルール|制約)(?:を|は)(?:すべて|全て|全部)?無視"),
            _c(r"新しい(?:指示|命令|ルール)\s*[:：は]"),
        ),
    ),
    "system_prompt_extraction": (
        0.7,
        (
            _c(
                r"\b(?:reveal|show|print|display|output|repeat|tell\s+me|give\s+me|write\s+out|dump|leak|disclose|list)\b"
                r".{0,30}?\b(?:your|the)\s+(?:full\s+|entire\s+|exact\s+|original\s+|hidden\s+|initial\s+|secret\s+)?"
                r"(?:system\s+prompt|system\s+message|initial\s+(?:prompt|instructions)|hidden\s+(?:prompt|instructions)"
                r"|instructions\s+(?:you\s+were\s+given|above)|developer\s+(?:message|prompt)|pre-?prompt|meta[\s-]?prompt)"
            ),
            _c(
                r"\bwhat\s+(?:is|are|was|were)\s+your\s+(?:system\s+prompt|initial\s+instructions|original\s+instructions|hidden\s+instructions)\b"
            ),
            _c(r"\brepeat\s+(?:the\s+)?(?:text|words|everything|all)\s+above\b"),
            _c(r"\b(?:verbatim|word\s+for\s+word)\b.{0,40}?\b(?:above|system\s+prompt|instructions)\b"),
            _c(
                r"(?:システムプロンプト|初期プロンプト|最初の指示|元の指示|隠された指示|内部の?指示|あなたの設定|開発者メッセージ)"
                r"(?:を|の内容を|の全文を)?(?:すべて|全て)?.{0,10}?(?:教えて|表示|出力|見せ|書き出|開示|そのまま|繰り返)"
            ),
            _c(r"上記の(?:文章|テキスト|内容|指示)を(?:そのまま|一字一句)"),
        ),
    ),
    "roleplay_jailbreak": (
        0.65,
        (
            _c(
                r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b|\bjailbr(?:eak|oken)(?:ed|ing)?\b|\bdeveloper\s+mode\s+(?:enabled|on|activated)\b|\bgod\s+mode\b"
            ),
            _c(
                r"\b(?:pretend|imagine|act|behave|roleplay|role-play)\b.{0,20}?\b(?:you\s+are|to\s+be|as|like)\b.{0,40}?"
                r"\b(?:unrestricted|unfiltered|uncensored|evil|amoral|without\s+(?:any\s+)?(?:restrictions|limits|rules|filters|guidelines)"
                r"|no\s+(?:restrictions|rules|limits|filters|guidelines))\b"
            ),
            _c(r"\byou\s+(?:are\s+)?no\s+longer\s+(?:bound|restricted|limited)\b"),
            _c(
                r"\bwithout\s+(?:any\s+)?(?:ethical|moral|safety)\s+(?:restrictions|guidelines|constraints|limits)\b"
            ),
            _c(
                r"\b(?:ignore|bypass|disable|turn\s+off)\b.{0,20}?\b(?:safety|content)\s+(?:filters?|polic(?:y|ies)|guidelines|restrictions)\b"
            ),
            _c(
                r"(?:制限|制約|フィルター|フィルタ|検閲|倫理(?:規定)?)(?:の|が)?(?:ない|無い|なし|無し|を解除|を外し|を無視|を無効)"
            ),
            _c(r"脱獄|ジェイルブレイク|開発者モード|DANモード"),
            _c(
                r"(?:今から|これから|以降)(?:あなたは|お前は|君は).{0,30}?(?:として|になりきって|を演じ|になって)"
            ),
        ),
    ),
    "obfuscated_instruction": (
        0.8,
        (
            _c(
                r"\b(?:decode|decrypt|deobfuscate|translate|convert)\b.{0,40}?\b(?:base64|rot13|hex|binary|morse|unicode)\b"
                r".{0,60}?\b(?:follow|execute|obey|do\s+(?:what|as)|run|perform|comply)\b"
            ),
            _c(
                r"(?:base64|rot13|16進数?|バイナリ).{0,20}?(?:デコード|復号|変換).{0,30}?(?:従|実行|その通り)"
            ),
        ),
    ),
    "tool_abuse": (
        0.75,
        (
            _c(
                r"\b(?:call|invoke|use|run|execute|trigger)\b.{0,15}?\b(?:the\s+)?[\w.-]{2,40}\s+(?:tool|function|plugin|action)\b"
                r".{0,40}?\b(?:send|email|post|upload|delete|remove|transfer|exfiltrate|forward|write|drop|purchase|pay)\b"
            ),
            _c(
                r"\b(?:execute|run)\s+(?:the\s+following\s+|this\s+)?(?:shell\s+|system\s+|bash\s+|terminal\s+|os\s+)(?:command|code|script)s?\b"
            ),
            _c(
                r"\b(?:send|forward|email|post|upload|exfiltrate|leak)\b.{0,30}?\b(?:all|the|every|entire|whole|full)\b.{0,20}?"
                r"\b(?:conversation|chat\s+history|history|emails|files|documents|data|secrets?|credentials|api\s+keys?|passwords?|tokens)\b"
                r".{0,40}?\b(?:to|at)\b"
            ),
            _c(r"rm\s+-rf\s+/|(?:curl|wget)\s+[^|\n]{1,100}\|\s*(?:ba)?sh\b"),
            _c(
                r"(?:ツール|関数|プラグイン|API)を(?:使って|呼び出して|実行して).{0,30}?(?:送信|削除|転送|書き込|アップロード|実行|購入)"
            ),
            _c(r"(?:コマンド|スクリプト|シェル)を実行"),
            _c(
                r"(?:会話履歴|履歴|メール|ファイル|パスワード|APIキー|認証情報|秘密|機密).{0,20}?(?:を|すべて|全て).{0,20}?(?:送信|転送|送って|アップロード)"
            ),
        ),
    ),
    "markdown_exfiltration": (
        0.8,
        (
            _c(
                r"https?://[^\s)\"'<>]{1,200}(?:\{|%7b)\s*(?:conversation|history|chat|data|secret|password|api_?key|token|user|input|context|summary)"
            ),
            _c(
                r"\b(?:render|display|show|include|output|embed|insert)\b.{0,30}?\b(?:image|markdown|img)\b.{0,80}?https?://"
            ),
            _c(r"(?:画像|リンク|マークダウン|img).{0,20}?(?:表示|埋め込|出力|挿入).{0,60}?https?://"),
            _c(
                r"!\[[^\]]{0,100}\]\(\s*https?://[^)\s?]{1,300}\?(?:[^)\s&]{0,100}&){0,5}(?:q|d|data|c|content|s|secret|token|key|p|payload|msg|m|h|history|conv|info|x)=[^)\s]{0,300}\)"
            ),
        ),
    ),
    "delimiter_injection": (
        0.5,
        (
            _c(r"<\|(?:im_start|im_end|endoftext|system|user|assistant)\|>|\[/?INST\]|<</?SYS>>"),
            _c(r"<\s*/?\s*(?:system|instructions?|developer|system_prompt)\s*>"),
            _c(
                r"\bBEGIN\s+(?:SYSTEM|NEW|ADMIN)\s+(?:PROMPT|INSTRUCTIONS?|MESSAGE)\b|^\s*#{2,3}\s*(?:system|new\s+instructions?)\s*:?\s*$"
            ),
        ),
    ),
}

_WEAK_MD_IMAGE = _c(
    r"!\[[^\]]{0,100}\]\(\s*https?://[^)\s?]{1,300}\?[^)\s]{1,300}\)|<img\b[^>]{0,100}\bsrc\s*=\s*[\"']?https?://[^\"'>\s?]{1,300}\?"
)
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,4096}={0,2}")


@dataclass(frozen=True, slots=True)
class InjectionFinding:
    family: str
    snippet: str
    strength: float
    source: str = "text"  # text / base64 / tag_chars / invisible


@dataclass(slots=True)
class InjectionResult:
    findings: list[InjectionFinding] = field(default_factory=list)
    invisible_chars: int = 0
    tag_chars: int = 0

    @property
    def families(self) -> list[str]:
        return sorted({f.family for f in self.findings})

    @property
    def score(self) -> float:
        best: dict[str, float] = {}
        for f in self.findings:
            best[f.family] = max(best.get(f.family, 0.0), f.strength)
        p = 1.0
        for v in best.values():
            p *= 1.0 - v
        return round(1.0 - p, 3)

    @property
    def detected(self) -> bool:
        return self.score >= 0.3


def _snippet(text: str, m: re.Match[str], pad: int = 20) -> str:
    a, b = max(0, m.start() - pad), min(len(text), m.end() + pad)
    return text[a:b].replace("\n", " ")[:160]


def _invisible_scan(raw: str) -> tuple[int, int, str]:
    """Return (zero-width/bidi count, tag-char count, decoded tag-char text)."""
    inv = tag = 0
    hidden: list[str] = []
    for ch in raw:
        cp = ord(ch)
        if cp in _ZERO_WIDTH or cp in _BIDI:
            inv += 1
        elif 0xE0000 <= cp <= 0xE007F:
            tag += 1
            if 0xE0020 <= cp <= 0xE007E:
                hidden.append(chr(cp - 0xE0000))
    return inv, tag, "".join(hidden)


def normalize_prompt(text: str) -> str:
    t = unicodedata.normalize("NFKC", text[:MAX_PROMPT_CHARS])
    t = "".join(
        ch
        for ch in t
        if ord(ch) not in _ZERO_WIDTH and ord(ch) not in _BIDI and not 0xE0000 <= ord(ch) <= 0xE007F
    )
    return re.sub(r"[ \t\r\f\v]+", " ", t)


def _match_families(text: str, source: str) -> list[InjectionFinding]:
    out: list[InjectionFinding] = []
    for family, (strength, patterns) in _FAMILY_PATTERNS.items():
        for pat in patterns:
            m = pat.search(text)
            if m:
                out.append(InjectionFinding(family, _snippet(text, m), strength, source))
                break
    if not any(f.family == "markdown_exfiltration" for f in out):
        m = _WEAK_MD_IMAGE.search(text)
        if m:
            out.append(InjectionFinding("markdown_exfiltration", _snippet(text, m), 0.35, source))
    return out


def _decode_b64_segments(text: str, limit: int = 4) -> list[str]:
    out: list[str] = []
    for m in _B64_RE.finditer(text):
        seg = m.group(0)
        if len(seg) % 4:
            seg = seg + "=" * (-len(seg) % 4)
        try:
            raw = base64.b64decode(seg, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            dec = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for c in dec if c.isprintable() or c in "\n\t")
        if dec and printable / len(dec) > 0.9 and any(c.isalpha() for c in dec):
            out.append(dec[:MAX_PROMPT_CHARS])
        if len(out) >= limit:
            break
    return out


def analyze_prompt(text: str | None) -> InjectionResult:
    """Scan one prompt (already extracted from the request) for injection / jailbreak patterns."""
    res = InjectionResult()
    if not text:
        return res
    raw = text[:MAX_PROMPT_CHARS]
    inv, tag, hidden = _invisible_scan(raw)
    res.invisible_chars, res.tag_chars = inv, tag
    norm = normalize_prompt(raw)
    res.findings.extend(_match_families(norm, "text"))
    if hidden.strip():
        hf = _match_families(normalize_prompt(hidden), "tag_chars")
        res.findings.append(
            InjectionFinding(
                "obfuscated_instruction", f"tag-char hidden text: {hidden[:80]}", 0.8, "tag_chars"
            )
        )
        res.findings.extend(hf)
    elif inv >= 5:
        res.findings.append(
            InjectionFinding(
                "obfuscated_instruction", f"{inv} invisible/bidi control chars", 0.4, "invisible"
            )
        )
    for dec in _decode_b64_segments(norm):
        df = _match_families(normalize_prompt(dec), "base64")
        if df:
            res.findings.append(
                InjectionFinding("obfuscated_instruction", f"base64 -> {dec[:80]}", 0.8, "base64")
            )
            res.findings.extend(df)
    return res


# ---------------------------------------------------------------------------------------------------------------
# Prompt extraction from HTTP requests to LLM apps

_PROMPT_KEYS = frozenset(
    {
        "messages",
        "content",
        "prompt",
        "input",
        "query",
        "message",
        "text",
        "question",
        "instructions",
        "parts",
        "q",
        "user_input",
        "inputs",
    }
)
_TRUSTED_ROLES = frozenset({"system", "developer"})


def _collect_strings(obj: Any, out: list[str], depth: int = 0, keyed: bool = False) -> None:
    if depth > 6 or sum(len(s) for s in out) > MAX_PROMPT_CHARS:
        return
    if isinstance(obj, dict):
        role = obj.get("role")
        if isinstance(role, str) and role.lower() in _TRUSTED_ROLES:
            return  # the application's own system prompt is not attacker input
        for k, v in obj.items():
            _collect_strings(v, out, depth + 1, keyed or str(k).lower() in _PROMPT_KEYS)
    elif isinstance(obj, list):
        for v in obj[:64]:
            _collect_strings(v, out, depth + 1, keyed)
    elif isinstance(obj, str) and keyed:
        out.append(obj)


def extract_prompt_text(body: str | None, content_type: str | None = None, query: str | None = None) -> str:
    parts: list[str] = []
    if body:
        b = body[: MAX_PROMPT_CHARS * 2]
        data: Any = None
        if "json" in (content_type or "").lower() or b.lstrip()[:1] in ("{", "["):
            try:
                data = json.loads(b)
            except (ValueError, RecursionError):
                data = None
        if data is not None:
            _collect_strings(data, parts, keyed=isinstance(data, str))
            if not parts and isinstance(data, dict | list):
                _collect_strings(data, parts, keyed=True)  # unknown schema: scan every string
        elif "x-www-form-urlencoded" in (content_type or "").lower():
            try:
                parts.extend(v for _, v in parse_qsl(b, keep_blank_values=False, max_num_fields=64))
            except ValueError:
                parts.append(b)
        else:
            parts.append(b)
    if query:
        with contextlib.suppress(ValueError):
            parts.extend(
                v for k, v in parse_qsl(query[:4096], max_num_fields=32) if k.lower() in _PROMPT_KEYS
            )
    return "\n".join(parts)[:MAX_PROMPT_CHARS]


def path_matches(path: str | None, prefixes: Iterable[str]) -> bool:
    p = (path or "").split("?", 1)[0]
    if not p:
        return False
    for pref in prefixes:
        base = pref.rstrip("/") or "/"
        if p == base or p.startswith(base + "/"):
            return True
    return False
