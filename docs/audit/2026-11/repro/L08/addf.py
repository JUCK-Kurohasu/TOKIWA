import json, sys
F="$AUDIT_DIR/findings/L08-llm.jsonl"
obj=json.load(open(sys.argv[1], encoding="utf-8"))
with open(F,"a",encoding="utf-8") as f: f.write(json.dumps(obj,ensure_ascii=False)+"\n")
print("appended", obj["id"])
