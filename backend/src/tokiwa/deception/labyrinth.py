"""Labyrinth: a deterministic maze of plausible, inert pages that wastes an automated crawler's time/tokens.

Pages are generated from (asset seed, path) only, so the same URL always shows the same page and nothing has to
be stored. The Gate serves pre-rendered bodies (``DecoyRoute`` is static), therefore we pre-render the first
``max_pages`` pages breadth-first and add a wildcard route for everything else below the prefix. Links never
leave the prefix; at ``max_depth`` they wrap back to the top level, so the maze is endless but bounded in size.

Pages carry ``<meta name="robots" content="noindex,nofollow">`` so well-behaved search crawlers stay out; LLM
agents and attack tooling usually ignore it. No scripts, no external resources.
"""

from __future__ import annotations

import hashlib
import html
import random
from dataclasses import dataclass

# (en, ja) word pairs used for titles/slugs
_WORDS: list[tuple[str, str]] = [
    ("quarterly", "四半期"),
    ("archive", "アーカイブ"),
    ("finance", "財務"),
    ("payroll", "給与"),
    ("customer", "顧客"),
    ("exports", "エクスポート"),
    ("infrastructure", "基盤"),
    ("runbook", "手順書"),
    ("backup", "バックアップ"),
    ("credentials", "認証情報"),
    ("migration", "移行"),
    ("legacy", "旧システム"),
    ("audit", "監査"),
    ("internal", "社内"),
    ("reports", "報告書"),
    ("snapshots", "スナップショット"),
    ("contracts", "契約"),
    ("vendor", "取引先"),
    ("keys", "鍵"),
    ("notes", "メモ"),
]

_SENTENCES_EN = [
    "This index is generated nightly from the document management system.",
    "Older revisions are kept for compliance and are read-only.",
    "Entries marked confidential require the ops VPN for download.",
    "Some links may point to records that were moved during the migration.",
    "Contact the platform team if an export appears to be incomplete.",
    "Checksums are published alongside each archive bundle.",
]
_SENTENCES_JA = [
    "この一覧は文書管理システムから毎晩自動生成されています。",
    "旧版はコンプライアンスのため読み取り専用で保管しています。",
    "機密指定の項目のダウンロードには運用 VPN が必要です。",
    "移行に伴い、一部のリンク先は移動している場合があります。",
]

BRANCHING = 3
DEFAULT_MAX_PAGES = 40


def normalize_base(path: str | None, default: str) -> str:
    """Asset path ("/archive/*" or "/archive") -> base prefix "/archive/"."""
    base = (path or default).rstrip("*") or default
    if not base.startswith("/"):
        base = "/" + base
    if not base.endswith("/"):
        base += "/"
    return base


def _rng(seed: str, rel: str) -> random.Random:
    digest = hashlib.sha256(f"{seed}|{rel}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _slug(rng: random.Random) -> tuple[str, str, str]:
    a, b = rng.sample(_WORDS, 2)
    year = rng.choice(["2021", "2022", "2023", "2024", "2025"])
    suffix = f"{rng.getrandbits(16):04x}"
    slug = f"{a[0]}-{b[0]}-{year}-{suffix}"
    title_en = f"{a[0].capitalize()} {b[0]} {year}"
    title_ja = f"{a[1]} {b[1]} {year}"
    return slug, title_en, title_ja


def rel_segments(base: str, path: str) -> list[str] | None:
    """Segments of ``path`` below ``base`` (None when outside the labyrinth)."""
    root = base.rstrip("/")
    if path != root and not path.startswith(base):
        return None
    rest = path[len(base) :] if path.startswith(base) else ""
    return [s for s in rest.split("/") if s]


def depth_of(base: str, path: str) -> int | None:
    segs = rel_segments(base, path)
    return None if segs is None else len(segs)


@dataclass(frozen=True)
class Link:
    href: str
    title_en: str
    title_ja: str


def children(base: str, seed: str, segs: list[str], max_depth: int) -> list[Link]:
    """Links shown on the page at ``segs``. Deterministic; wraps to the top level at ``max_depth``."""
    if len(segs) >= max(1, max_depth):
        segs = []  # wrap: endless, but the set of distinct pages stays bounded
    rng = _rng(seed, "/".join(segs))
    out: list[Link] = []
    for _ in range(BRANCHING):
        slug, en, ja = _slug(rng)
        out.append(Link(base + "/".join([*segs, slug]) + "/", en, ja))
    return out


def page_title(seed: str, segs: list[str]) -> tuple[str, str]:
    if not segs:
        return "Document archive", "文書アーカイブ"
    _slug_unused, en, ja = _slug(_rng(seed, "title|" + "/".join(segs)))
    return en, ja


def render_page(
    base: str,
    seed: str,
    path: str,
    *,
    max_depth: int,
    language: str = "both",
    canary_html: str = "",
) -> str:
    segs = rel_segments(base, path) or []
    en, ja = page_title(seed, segs)
    rng = _rng(seed, "text|" + "/".join(segs))
    paras: list[str] = []
    if language in ("en", "both"):
        paras += rng.sample(_SENTENCES_EN, 2)
    if language in ("ja", "both"):
        paras += rng.sample(_SENTENCES_JA, 1)
    title = ja if language == "ja" else en
    subtitle = f'<p class="sub">{html.escape(ja)}</p>\n' if language == "both" else ""
    crumbs = ['<a href="' + html.escape(base) + '">archive</a>']
    for i in range(len(segs)):
        href = base + "/".join(segs[: i + 1]) + "/"
        crumbs.append(f'<a href="{html.escape(href)}">{html.escape(segs[i])}</a>')
    items = []
    for link in children(base, seed, segs, max_depth):
        label = link.title_ja if language == "ja" else link.title_en
        items.append(f'<li><a href="{html.escape(link.href)}">{html.escape(label)}</a></li>')
    body = "\n".join(f"<p>{html.escape(p)}</p>" for p in paras)
    lang_attr = "ja" if language == "ja" else "en"
    return (
        f'<!doctype html>\n<html lang="{lang_attr}">\n<head><meta charset="utf-8">'
        f"<title>{html.escape(title)}</title>"
        '<meta name="robots" content="noindex,nofollow"></head>\n<body>\n'
        f"<nav>{' / '.join(crumbs)}</nav>\n<h1>{html.escape(title)}</h1>\n{subtitle}{body}\n"
        f"<ul>\n{chr(10).join(items)}\n</ul>\n{canary_html}\n</body>\n</html>\n"
    )


def prerender_paths(base: str, seed: str, *, max_depth: int, max_pages: int = DEFAULT_MAX_PAGES) -> list[str]:
    """Breadth-first page paths starting at the root, at most ``max_pages`` (root included)."""
    out = [base]
    seen = {base}
    queue: list[list[str]] = [[]]
    while queue and len(out) < max_pages:
        segs = queue.pop(0)
        if len(segs) >= max_depth:
            continue
        for link in children(base, seed, segs, max_depth):
            if link.href in seen:
                continue
            seen.add(link.href)
            out.append(link.href)
            queue.append(rel_segments(base, link.href) or [])
            if len(out) >= max_pages:
                break
    return out
