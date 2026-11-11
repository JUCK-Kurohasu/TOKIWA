#!/usr/bin/env python3
"""Regenerate the status diagram (Mermaid) in the audit epic from live issue states.

    python3 status_diagram.py          # rewrite the section between the markers in the epic body
    python3 status_diagram.py --dry    # print the section only (still reads issue states)

Why a script: a Mermaid block is static, so "which issues are done" has to be drawn from the current
open/closed state each time. The grouping lives in taxonomy.json next to this file; state and severity
are read from GitHub. Needs the `gh` CLI and a token that may edit the epic (GH_TOKEN in Actions).
"""

from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = os.environ.get("GITHUB_REPOSITORY") or "JUCK-Kurohasu/TOKIWA"
TAX = json.loads((HERE / "taxonomy.json").read_text(encoding="utf-8"))
EPIC, LABEL = TAX["epic"], TAX["label"]
START, END = "<!-- audit-status:start -->", "<!-- audit-status:end -->"
OPEN_MARK = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}
PER_LINE = 10
# One line per bundle keeps the tree short enough to scan; the default 200px label wrap would triple its height.
INIT = '%%{init: {"flowchart": {"nodeSpacing": 10, "rankSpacing": 36, "wrappingWidth": 760}}}%%'


def gh(args: list[str], inp: str | None = None):
    r = subprocess.run(["gh", "api", *args], input=inp, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise SystemExit(f"gh api {' '.join(args[:3])} failed: {r.stderr.strip()[:300]}")
    return json.loads(r.stdout) if r.stdout.strip() else None


def fetch() -> dict[int, dict]:
    out, page = {}, 1
    while True:
        chunk = gh([f"repos/{REPO}/issues?labels={LABEL}&state=all&per_page=100&page={page}"])
        for i in chunk:
            if "pull_request" in i:
                continue
            sev = next((lb["name"].split(":", 1)[1] for lb in i["labels"] if lb["name"].startswith("severity:")), "info")
            out[i["number"]] = {"closed": i["state"] == "closed", "reason": i.get("state_reason") or "", "sev": sev}
        if len(chunk) < 100:
            return out
        page += 1


def mark(n: int, st: dict[int, dict]) -> str:
    s = st.get(n)
    if s is None:
        return "❔"  # in taxonomy.json but not found on GitHub (deleted / label removed)
    if s["closed"]:
        return "✅" if s["reason"] in ("completed", "") else "➖"
    return OPEN_MARK.get(s["sev"], "⚪")


def done(nums: list[int], st: dict[int, dict]) -> int:
    return sum(1 for n in nums if st.get(n, {}).get("closed"))


def cls(d: int, total: int) -> str:
    return "done" if total and d == total else ("part" if d else "")


def build(st: dict[int, dict]) -> str:
    q = lambda s: s.replace('"', "'")  # noqa: E731
    lines, classes = [INIT, "flowchart LR"], {"done": [], "part": []}
    all_nums = [n for s in TAX["streams"] for g in s["groups"] for n in g["issues"]]
    known = set(all_nums) | set(TAX.get("exclude", []))
    extra = sorted(n for n in st if n not in known)
    total_done = done(all_nums + extra, st)
    lines.append(f'  R(["監査 2026-11<br/>完了 {total_done} / {len(all_nums) + len(extra)}"])')
    if c := cls(total_done, len(all_nums) + len(extra)):
        classes[c].append("R")
    streams = list(TAX["streams"])
    if extra:  # labelled issues nobody has classified yet: never hide them
        streams.append({"key": "U", "name": "未分類（taxonomy.json に追加する）", "groups": [{"name": "未分類", "issues": extra}]})
    for s in streams:
        nums = [n for g in s["groups"] for n in g["issues"]]
        d = done(nums, st)
        lines.append(f'  R --> {s["key"]}["{s["key"]} {q(s["name"])}<br/>{d} / {len(nums)}"]')
        if c := cls(d, len(nums)):
            classes[c].append(s["key"])
        for k, g in enumerate(s["groups"], 1):
            nid = f'{s["key"]}{k}'
            chips = [f"{mark(n, st)}{n}" for n in g["issues"]]
            rows = "<br/>".join(" ".join(chips[i : i + PER_LINE]) for i in range(0, len(chips), PER_LINE))
            short = re.sub(r"（[^）]*）", "", g["name"])  # details stay in taxonomy.json; the diagram needs one line
            lines.append(f'  {s["key"]} --> {nid}["{q(short)}： {rows}"]')
            if c := cls(done(g["issues"], st), len(g["issues"])):
                classes[c].append(nid)
    lines.append("  classDef done fill:#d1fae5,stroke:#059669,color:#064e3b")
    lines.append("  classDef part fill:#fef3c7,stroke:#d97706,color:#78350f")
    lines += [f"  class {','.join(v)} {k}" for k, v in classes.items() if v]
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cross = "\n".join(
        f"| {c['name']} | {c['streams']} | {done(c['issues'], st)} / {len(c['issues'])} | " + " ".join(f"{mark(n, st)}#{n}" for n in c["issues"]) + " |"
        for c in TAX.get("cross_cutting", [])
    )
    return f"""{START}
## 系統図と進捗

完了 **{total_done} / {len(all_nums) + len(extra)}**（状態の取得: {now}）

```mermaid
{chr(10).join(lines)}
```

- 数字は Issue 番号。未完了は重大度の色（🔴 high / 🟠 medium / 🟡 low / ⚪ info）、✅ 完了、➖ 対応しない・重複。枠が緑 = その束はすべて完了、黄 = 一部完了。
- 系統（A〜K）は「修正で主に触るコードの場所」、その下は原因別の束です（分類は監査側の解釈。定義は `docs/audit/2026-11/tools/taxonomy.json`）。
- この節は機械生成です。Issue を閉じる・開き直すと `.github/workflows/audit-epic.yml` が描き直します（手動: `python3 docs/audit/2026-11/tools/status_diagram.py`）。この節の外は書き換えません。

### 系統をまたぐ束（同じ原因を複数の系統が持つもの。担当を分ける前に方針を 1 つ決める）

| テーマ | またがる系統 | 完了 | Issue |
|---|---|---|---|
{cross}
{END}"""


def main() -> None:
    st = fetch()
    section = build(st)
    if "--dry" in sys.argv:
        print(section)
        return
    body = gh([f"repos/{REPO}/issues/{EPIC}"])["body"] or ""
    strip_ts = lambda s: re.sub(r"（状態の取得: [^）]*）", "", s)  # noqa: E731
    if START in body and END in body:
        a, b = body.index(START), body.index(END) + len(END)
        if strip_ts(body[a:b]).split() == strip_ts(section).split():
            print("no change")
            return
        new = body[:a] + section + body[b:]
    else:
        anchor = "## これは何か"
        new = body.replace(anchor, section + "\n\n" + anchor, 1) if anchor in body else section + "\n\n" + body
    gh(["-X", "PATCH", f"repos/{REPO}/issues/{EPIC}", "--input", "-"], json.dumps({"body": new}))
    print(f"updated #{EPIC}: {len(new)} chars")


if __name__ == "__main__":
    main()
