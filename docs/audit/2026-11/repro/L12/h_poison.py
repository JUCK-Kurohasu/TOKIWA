"""POST an ingest batch: 1 benign event + 1 event whose method is 17+ chars (or NUL in UA). Observe status and what got stored."""
import json, sys, httpx, uuid
tok = open(sys.argv[1]).read().strip(); variant = sys.argv[2]
def ev(method="GET", ua="Mozilla/5.0", host="app.lab", path="/"):
    return {"kind": "http", "dataset": "nginx.access", "source": {"ip": "203.0.113.5"},
            "http": {"method": method, "host": host, "path": path, "user_agent": ua, "status": 200}}
bad = {"method": ev(method="A" * 20), "host": ev(host="a" * 300 + ".lab"), "nul": ev(ua="curl\x00x"), "none": ev()}[variant]
marker = "/benign-" + uuid.uuid4().hex[:8]
r = httpx.post("http://127.0.0.1:18550/api/v1/ingest/events", headers={"X-Tokiwa-Token": tok},
               json={"events": [ev(path=marker), bad]}, timeout=30)
print(variant, "HTTP", r.status_code, r.text[:120].replace("\n", " "))
print("marker", marker)
