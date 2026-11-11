import json, sys
F = "$AUDIT_DIR/findings/L05-webdetect.jsonl"
def add(obj):
    req = ["id","title","area","category","severity","confidence","summary","evidence","attack_scenario","recommendation","effort","known","references","related"]
    for k in req: assert k in obj, k
    with open(F, "a", encoding="utf-8") as f: f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    print("wrote", obj["id"])
