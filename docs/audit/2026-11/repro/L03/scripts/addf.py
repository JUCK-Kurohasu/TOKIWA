import json, sys
F = "$AUDIT_DIR/findings/L03-canary.jsonl"
obj = json.loads(sys.stdin.read())
for k in ("id","title","area","category","severity","confidence","summary","evidence","attack_scenario","recommendation","effort","known","references","related"):
    assert k in obj, k
with open(F, "a", encoding="utf-8") as f:
    f.write(json.dumps(obj, ensure_ascii=False) + "\n")
print("appended", obj["id"])
