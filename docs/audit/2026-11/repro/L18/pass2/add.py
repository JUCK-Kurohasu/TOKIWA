import json,sys
F="$AUDIT_DIR/findings/L18-day2ops.jsonl"
o=json.load(open(sys.argv[1]))
open(F,"a").write(json.dumps(o,ensure_ascii=False)+"\n"); print("added",o["id"])
