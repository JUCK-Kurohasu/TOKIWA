"""Append one finding (JSON from a file or stdin) to the L12 JSONL."""
import json, sys
p = "$AUDIT_DIR/findings/L12-sensors-intel.jsonl"
obj = json.load(open(sys.argv[1], encoding="utf-8")) if len(sys.argv) > 1 else json.load(sys.stdin)
req = ["id","title","area","category","severity","confidence","summary","evidence","attack_scenario","recommendation","effort","known","references","related"]
missing = [k for k in req if k not in obj]
assert not missing, missing
with open(p, "a", encoding="utf-8") as f:
    f.write(json.dumps(obj, ensure_ascii=False) + "\n")
print("appended", obj["id"])
