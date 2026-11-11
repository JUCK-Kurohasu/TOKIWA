import json,sys
F="$AUDIT_DIR/findings/L03-canary.jsonl"
def add(o):
    with open(F,"a",encoding="utf-8") as f: f.write(json.dumps(o,ensure_ascii=False)+"\n")
    print("added",o["id"])
