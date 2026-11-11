"""Append one finding (python dict literal file or stdin JSON) to the lane JSONL."""
import json, sys, os
F = os.environ["AUDIT_DIR"] + "/findings/L06-gate.jsonl"
obj = json.loads(sys.stdin.read())
req = ["id","title","area","category","severity","confidence","summary","evidence","attack_scenario","recommendation","effort","known","references","related"]
missing = [k for k in req if k not in obj]
assert not missing, missing
with open(F, "a", encoding="utf-8") as f: f.write(json.dumps(obj, ensure_ascii=False) + "\n")
print("ok", obj["id"], sum(1 for _ in open(F)))
