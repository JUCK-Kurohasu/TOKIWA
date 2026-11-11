import json,sys
obj=json.loads(sys.stdin.read())
with open("$AUDIT_DIR/findings/L12-sensors-intel.jsonl","a",encoding="utf-8") as f:
    f.write(json.dumps(obj,ensure_ascii=False)+"\n")
print("ok",obj["id"])
