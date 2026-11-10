"""Append one finding (JSON object read from a file given as argv[1]) to the L01 JSONL, validating fields."""
import json, sys
OUT = "$AUDIT_DIR/findings/L01-artex.jsonl"
REQ = ["id","title","area","category","severity","confidence","summary","evidence","attack_scenario","recommendation","effort","known","references","related"]
obj = json.load(open(sys.argv[1], encoding="utf-8"))
items = obj if isinstance(obj, list) else [obj]
existing = set()
try:
    for line in open(OUT, encoding="utf-8"):
        existing.add(json.loads(line)["id"])
except FileNotFoundError:
    pass
with open(OUT, "a", encoding="utf-8") as f:
    for it in items:
        missing = [k for k in REQ if k not in it]
        assert not missing, (it.get("id"), missing)
        assert it["id"] not in existing, ("dup", it["id"])
        f.write(json.dumps(it, ensure_ascii=False) + "\n")
        existing.add(it["id"])
        print("wrote", it["id"])
