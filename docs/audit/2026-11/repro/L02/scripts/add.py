"""Append findings (JSON objects in a file passed as argv[1]) to the L02 JSONL."""
import json, sys
OUT = "$AUDIT_DIR/findings/L02-field.jsonl"
REQ = ["id","title","area","category","severity","confidence","summary","evidence","attack_scenario","recommendation","effort","known","references","related"]
items = json.load(open(sys.argv[1], encoding="utf-8"))
with open(OUT, "a", encoding="utf-8") as f:
    for it in items:
        missing = [k for k in REQ if k not in it]
        assert not missing, (it.get("id"), missing)
        f.write(json.dumps(it, ensure_ascii=False) + "\n")
print("appended", [i["id"] for i in items])
