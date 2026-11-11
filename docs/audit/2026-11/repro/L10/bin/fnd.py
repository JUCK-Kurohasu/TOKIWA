"""Upsert one finding (JSON object on stdin) into the L10 JSONL by id."""
import json, sys, pathlib
P = pathlib.Path("$AUDIT_DIR/findings/L10-frontend.jsonl")
obj = json.loads(sys.stdin.read())
base = {"area":"frontend","effort":"S","known":"none","references":[],"related":[]}
base.update(obj); obj = base
req = ["id","title","area","category","severity","confidence","summary","evidence","attack_scenario","recommendation","effort","known","references","related"]
missing = [k for k in req if k not in obj]
assert not missing, missing
lines = P.read_text(encoding="utf-8").splitlines() if P.exists() else []
out, done = [], False
for ln in lines:
    if not ln.strip(): continue
    o = json.loads(ln)
    if o["id"] == obj["id"]:
        out.append(json.dumps(obj, ensure_ascii=False)); done = True
    else:
        out.append(ln)
if not done: out.append(json.dumps(obj, ensure_ascii=False))
P.write_text("\n".join(out) + "\n", encoding="utf-8")
print(("updated " if done else "added ") + obj["id"], len(out), "findings")
