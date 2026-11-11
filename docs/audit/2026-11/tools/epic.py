#!/usr/bin/env python3
"""Rebuild the epic (#16) body from issues/index.json + issues/filed.json and PATCH it via gh api."""
import json, subprocess, sys, collections, datetime
from pathlib import Path
A = Path(__file__).resolve().parent; I = A / "issues"
idx = json.loads((I / "index.json").read_text()); filed = json.loads((I / "filed.json").read_text())
SEV = ["critical", "high", "medium", "low", "info"]; CONF = ["confirmed", "likely", "hypothesis"]
CJ = {"confirmed": "再現済み", "likely": "コード確認", "hypothesis": "推測"}
def lab(e, p): return next((l.split(":", 1)[1] for l in e["labels"] if l.startswith(p + ":")), "?")
rows = [dict(n=filed[e["key"]]["number"], sev=lab(e, "severity"), conf=lab(e, "confidence"), area=lab(e, "area"),
             title=e["title"].split("] ", 1)[-1], llm="needs-live-llm" in e["labels"]) for e in idx if e["key"] in filed]
c = collections.Counter((r["sev"], r["conf"]) for r in rows)
counts = "| 重大度 | " + " | ".join(CONF) + " | 計 |\n|---|" + "---:|" * (len(CONF) + 1) + "\n"
for s in SEV:
    t = sum(c[(s, k)] for k in CONF)
    if t: counts += f"| **{s}** | " + " | ".join(str(c[(s, k)]) for k in CONF) + f" | {t} |\n"
counts += f"| 計 | " + " | ".join(str(sum(c[(s, k)] for s in SEV)) for k in CONF) + f" | {len(rows)} |"
tables = ""
for s in SEV:
    rs = sorted((r for r in rows if r["sev"] == s), key=lambda r: (r["area"], r["n"]))
    if not rs: continue
    tables += f"### {s}（{len(rs)} 件）\n\n| Issue | 領域 | 内容 | 確度 |\n|---|---|---|---|\n"
    for r in rs:
        t = r["title"].replace("|", "\\|").replace("\n", " ")
        tables += f"| #{r['n']} | `{r['area']}` | {t}{' ⚠️要実LLM' if r['llm'] else ''} | {CJ.get(r['conf'], r['conf'])} |\n"
    tables += "\n"
body = (A / "epic_head.md").read_text().replace("{{N}}", str(len(rows))).replace("{{DATE}}", datetime.date.today().isoformat()) \
    .replace("{{COUNTS}}", counts).replace("{{TABLES}}", tables.rstrip())
(A / "epic_body.md").write_text(body); print("body chars", len(body))
if "--dry" not in sys.argv:
    r = subprocess.run(["gh", "api", "-X", "PATCH", "repos/JUCK-Kurohasu/TOKIWA/issues/16", "--input", "-", "--jq", ".html_url"],
                       input=json.dumps({"body": body}), capture_output=True, text=True)
    print(r.stdout.strip() or r.stderr.strip()[:300])
    subprocess.run([sys.executable, str(A / "status_diagram.py")], check=False)  # refill the status diagram section
