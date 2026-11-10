"""Upsert a finding (by id) into the L09 JSONL. Usage: python fw.py <finding.py> (file defines dict F)."""
import json, sys, runpy, pathlib
OUT = pathlib.Path("$AUDIT_DIR/findings/L09-respond.jsonl")
F = runpy.run_path(sys.argv[1])["F"]
rows = []
if OUT.exists():
    rows = [json.loads(l) for l in OUT.read_text(encoding="utf-8").splitlines() if l.strip()]
rows = [r for r in rows if r.get("id") != F["id"]] + [F]
rows.sort(key=lambda r: r["id"])
OUT.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
print("ok", F["id"], len(rows))
