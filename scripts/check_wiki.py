#!/usr/bin/env python3
"""Consistency check for the multilingual wiki source in docs/wiki/.

Why: the wiki is published as-is by scripts/publish-wiki.sh, and GitHub wikis have no i18n support. Languages are
separate pages (``Page`` = Japanese default, ``Page-en`` / ``Page-zh`` / ``Page-es``) tied together by a language bar
on the first line. This script catches the mistakes that are easy to make by hand: a page missing in one language,
a wrong language bar, a link pointing to another language's page or to a page that does not exist, and translations
whose code blocks drifted (different number of fenced blocks than the Japanese original).

    python3 scripts/check_wiki.py [docs/wiki]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

LANGS = ("en", "zh", "es")
LANG_NAMES = {"ja": "日本語", "en": "English", "zh": "中文", "es": "Español"}
SPECIAL = {"_Sidebar", "_Footer", "README"}
# Wiki-internal links: [text](Page-Name) — no scheme, slash, dot or anchor.
LINK = re.compile(r"\]\(([A-Za-z0-9][A-Za-z0-9-]*)\)")
FENCE = re.compile(r"^```", re.MULTILINE)


def page_name(base: str, lang: str) -> str:
    return base if lang == "ja" else f"{base}-{lang}"


def language_bar(base: str, lang: str) -> str:
    parts = []
    for code in ("ja", *LANGS):
        name = LANG_NAMES[code]
        parts.append(f"**{name}**" if code == lang else f"[{name}]({page_name(base, code)})")
    return "> 🌐 " + " · ".join(parts)


def main(root: Path) -> int:
    errors: list[str] = []
    stems = {p.stem for p in root.glob("*.md")}
    bases = sorted(s for s in stems if s not in SPECIAL and not re.search(r"-(en|zh|es)$", s))
    if "Home" not in bases:
        errors.append("Home.md (Japanese default page) is missing")

    for base in bases:
        ja_text = (root / f"{base}.md").read_text(encoding="utf-8")
        ja_fences = len(FENCE.findall(ja_text))
        for lang in ("ja", *LANGS):
            name = page_name(base, lang)
            path = root / f"{name}.md"
            if not path.is_file():
                errors.append(f"{name}.md: missing ({LANG_NAMES[lang]} version of {base})")
                continue
            text = path.read_text(encoding="utf-8")
            first, _, body = text.partition("\n")
            if first.strip() != language_bar(base, lang):
                errors.append(
                    f"{name}.md: first line must be the language bar:\n    {language_bar(base, lang)}"
                )
            for target in LINK.findall(body):
                if target not in stems:
                    errors.append(f"{name}.md: link to missing page '{target}'")
                elif lang == "ja" and re.search(r"-(en|zh|es)$", target):
                    errors.append(f"{name}.md: Japanese page links to another language ('{target}')")
                elif lang != "ja" and not target.endswith(f"-{lang}"):
                    errors.append(f"{name}.md: link '{target}' should point to the -{lang} page")
            if lang != "ja" and len(FENCE.findall(text)) != ja_fences:
                errors.append(
                    f"{name}.md: {len(FENCE.findall(text))} code fences, Japanese original has {ja_fences}"
                )

    sidebar = root / "_Sidebar.md"
    if sidebar.is_file():
        for target in LINK.findall(sidebar.read_text(encoding="utf-8")):
            if target not in stems:
                errors.append(f"_Sidebar.md: link to missing page '{target}'")
    else:
        errors.append("_Sidebar.md is missing")

    for e in errors:
        print(f"wiki: {e}", file=sys.stderr)
    if not errors:
        print(f"wiki: OK ({len(bases)} pages x {1 + len(LANGS)} languages)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "docs/wiki")))
