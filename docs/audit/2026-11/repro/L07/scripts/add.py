import json,sys
obj=json.load(open(sys.argv[1]))
with open("$AUDIT_DIR/findings/L07-api.jsonl","a") as f: f.write(json.dumps(obj,ensure_ascii=False)+"\n")
print("ok",obj["id"])
