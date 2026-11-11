#!/usr/bin/env python3
"""File rendered audit issues through the GitHub REST API (gh api) — no LLM involved.
Reconciles with what already exists (by exact title), creates the missing ones, attaches all to epic #16."""
import json, subprocess, sys, time, collections
from pathlib import Path
A = Path(__file__).resolve().parent; I = A / "issues"; REPO = "repos/JUCK-Kurohasu/TOKIWA"; EPIC = 16
DRY = "--dry" in sys.argv
def gh(args, inp=None):
    r = subprocess.run(["gh", "api", *args], input=inp, capture_output=True, text=True, timeout=60)
    if r.returncode != 0: raise RuntimeError(f"gh api {' '.join(args[:3])}: {r.stderr.strip()[:300]} {r.stdout[:200]}")
    return json.loads(r.stdout) if r.stdout.strip() else None
def existing():
    out, page = [], 1
    while True:
        chunk = gh([f"{REPO}/issues?state=all&labels=audit-2026-11&per_page=100&page={page}"])
        out += [i for i in chunk if "pull_request" not in i]
        if len(chunk) < 100: return out
        page += 1
index = json.loads((I / "index.json").read_text())
filed = json.loads((I / "filed.json").read_text()) if (I / "filed.json").exists() else {}
ex = existing(); by_title = collections.defaultdict(list)
for i in ex: by_title[i["title"]].append(i)
dups = {t: [i["number"] for i in v] for t, v in by_title.items() if len(v) > 1}
print(f"existing audit issues: {len(ex)}; duplicate titles: {dups or 'none'}")
for e in index:                       # reconcile: created on GitHub but not recorded
    hit = by_title.get(e["title"])
    if hit:
        first = min(hit, key=lambda i: i["number"])
        filed[e["key"]] = {"number": first["number"], "url": first["html_url"], "id": first["id"]}
todo = [e for e in index if e["key"] not in filed]
print(f"index {len(index)}, filed after reconcile {len(filed)}, to create {len(todo)}")
for e in todo:
    payload = {"title": e["title"], "body": Path(e["body_file"]).read_text(encoding="utf-8"), "labels": e["labels"]}
    if DRY: print("would create", e["key"], e["title"][:60]); continue
    for attempt in range(3):
        try:
            r = gh(["-X", "POST", f"{REPO}/issues", "--input", "-"], json.dumps(payload)); break
        except RuntimeError as err:
            print("retry", e["key"], str(err)[:160]); time.sleep(20 * (attempt + 1))
    else:
        print("FAILED", e["key"]); continue
    filed[e["key"]] = {"number": r["number"], "url": r["html_url"], "id": r["id"]}
    (I / "filed.json").write_text(json.dumps(filed, ensure_ascii=False, indent=1))
    print("created", e["key"], "#%d" % r["number"]); time.sleep(2)
(I / "filed.json").write_text(json.dumps(filed, ensure_ascii=False, indent=1))
if not DRY:                            # attach everything to the epic
    subs, page = set(), 1
    while True:
        chunk = gh([f"{REPO}/issues/{EPIC}/sub_issues?per_page=100&page={page}"]); subs |= {s["id"] for s in chunk}
        if len(chunk) < 100: break
        page += 1
    n = 0
    for k, v in filed.items():
        if v.get("id") and v["id"] not in subs:
            try: gh(["-X", "POST", f"{REPO}/issues/{EPIC}/sub_issues", "--input", "-"], json.dumps({"sub_issue_id": v["id"]})); n += 1; time.sleep(0.7)
            except RuntimeError as err: print("attach failed", k, str(err)[:160])
    print(f"attached {n} new sub-issues; epic now has {len(subs) + n}")
print("filed total:", len(filed))
