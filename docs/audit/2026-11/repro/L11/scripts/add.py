#!/usr/bin/env python3
"""Append one finding (JSON from a file path argv[1]) to L11 JSONL, replacing same id if present."""
import json, sys, pathlib
out = pathlib.Path("$AUDIT_DIR/findings/L11-ops.jsonl")
d = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
req = ["id","title","area","category","severity","confidence","summary","evidence","recommendation"]
miss = [k for k in req if not d.get(k)]
assert not miss, miss
lines = out.read_text(encoding="utf-8").splitlines() if out.exists() else []
lines = [l for l in lines if l.strip() and json.loads(l).get("id") != d["id"]]
lines.append(json.dumps(d, ensure_ascii=False))
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("ok", d["id"], len(lines))
