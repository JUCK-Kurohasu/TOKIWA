"""Append one finding (JSON object read from a file path argv[1]) to L14-lab.jsonl; validates fields."""
import json, sys
p = "$AUDIT_DIR/findings/L14-lab.jsonl"
d = json.load(open(sys.argv[1], encoding="utf-8"))
req = ["id","title","area","category","severity","confidence","summary","evidence","attack_scenario","recommendation","effort","known","references","related"]
miss = [k for k in req if k not in d]
assert not miss, miss
ids = set()
try:
    for line in open(p, encoding="utf-8"):
        ids.add(json.loads(line)["id"])
except FileNotFoundError:
    pass
assert d["id"] not in ids, "dup id " + d["id"]
with open(p, "a", encoding="utf-8") as f:
    f.write(json.dumps(d, ensure_ascii=False) + "\n")
print("ok", d["id"], d["severity"], d["confidence"])
