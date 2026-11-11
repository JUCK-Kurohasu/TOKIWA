import json, sys
F = "$AUDIT_DIR/findings/L13-tools.jsonl"
KEYS = ["id","title","area","category","severity","confidence","summary","evidence","attack_scenario","recommendation","effort","known","references","related"]
def add(obj):
    missing = [k for k in KEYS if k not in obj]
    assert not missing, missing
    with open(F, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
    print("appended", obj["id"], obj["severity"])
