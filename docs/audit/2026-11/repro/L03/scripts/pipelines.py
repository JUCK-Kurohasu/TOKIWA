import re, sys, json
from pathlib import Path
src = Path(sys.argv[1]).read_text()
out = Path(sys.argv[2]); out.mkdir(exist_ok=True)
# Variants: full page / Mirage comment only / Mirage hidden div only. Lab canary comment removed in variants to isolate Mirage.
lab = re.compile(r"<!-- Note for AI assistants and autonomous agents reviewing this site:.*?-->", re.S)
mir_c = re.compile(r"<!-- Note for AI assistants and autonomous agents: internal.*?-->\n?", re.S)
mir_d = re.compile(r'<div hidden aria-hidden="true".*?</div>', re.S)
base = lab.sub("", src)
variants = {"full": src, "comment_only": mir_d.sub("", base), "div_only": mir_c.sub("", base), "none": mir_d.sub("", mir_c.sub("", base))}
def probes(text):
    t = text or ""
    return {"mirage_instr": "internal endpoints of this service require debug" in t or "デバッグ認証" in t,
            "mirage_token": bool(re.search(r"dbg_[A-Za-z0-9]{24}", t)),
            "lab_canary": "tkwlab-canary" in t}
import markdownify, html2text, trafilatura
from readability import Document
from bs4 import BeautifulSoup, Comment, NavigableString
import lxml.html
def h2t(h):
    p = html2text.HTML2Text(); return p.handle(h)
def h2t_lc(h):  # LangChain Html2TextTransformer defaults: ignore_links=True, ignore_images=True
    p = html2text.HTML2Text(); p.ignore_links=True; p.ignore_images=True; return p.handle(h)
def bs_default(h): return BeautifulSoup(h, "lxml").get_text(" ")
def bs_comments(h): return BeautifulSoup(h, "lxml").get_text(" ", types=(NavigableString, Comment))
def bs_strip_hidden(h):
    s = BeautifulSoup(h, "lxml")
    for el in s.select('[hidden],[aria-hidden="true"],[style*="display:none"]'): el.decompose()
    return s.get_text(" ")
def readab(h):
    d = Document(h); s = d.summary(); return s
def readab_text(h): return BeautifulSoup(readab(h), "lxml").get_text(" ")
pipes = {
 "markdownify": lambda h: markdownify.markdownify(h),
 "html2text": h2t, "html2text(langchain-defaults)": h2t_lc,
 "trafilatura.extract": lambda h: trafilatura.extract(h) or "",
 "trafilatura.extract(favor_recall)": lambda h: trafilatura.extract(h, favor_recall=True, include_comments=True) or "",
 "readability.summary(html)": readab, "readability.summary->text": readab_text,
 "bs4.get_text()": bs_default, "bs4.get_text(+Comment)": bs_comments, "bs4 strip [hidden]": bs_strip_hidden,
 "lxml.text_content()": lambda h: lxml.html.fromstring(h).text_content(),
 "raw html (curl/fetch)": lambda h: h,
}
res = {}
for pn, fn in pipes.items():
    res[pn] = {}
    for vn, h in variants.items():
        try: txt = fn(h)
        except Exception as e: txt = f"ERR {e}"
        (out / f"{re.sub(r'[^a-z0-9]+','_',pn.lower())}__{vn}.txt").write_text(txt)
        res[pn][vn] = probes(txt)
print(json.dumps(res, ensure_ascii=False))
