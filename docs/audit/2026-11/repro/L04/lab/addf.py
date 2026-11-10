"""Append/replace a finding in the lane JSONL (by id). Usage: python addf.py <json-file>"""
import json, sys, pathlib
F = pathlib.Path("$AUDIT_DIR/findings/L04-aievasion.jsonl")
new = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
rows = [json.loads(l) for l in F.read_text(encoding="utf-8").splitlines() if l.strip()] if F.exists() else []
rows = [r for r in rows if r["id"] != new["id"]] + [new]
rows.sort(key=lambda r: r["id"])
F.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
print("ok", new["id"], len(rows), "findings")
