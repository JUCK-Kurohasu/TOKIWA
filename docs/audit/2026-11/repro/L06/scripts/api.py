"""Tiny admin API helper: python api.py METHOD PATH [json]. Logs in with the stored admin password."""
import json, os, sys, urllib.request
D = os.environ["D"]; BASE = "http://127.0.0.1:18250"
def call(method, path, body=None, tok=None):
    h = {"Content-Type": "application/json"}
    if tok: h["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None, headers=h)
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e: return e.code, e.read().decode()[:500]
def token():
    s, b = call("POST", "/api/v1/auth/login", {"username": "admin", "password": open(f"{D}/admin.pw").read().strip()})
    return b["access_token"]
if __name__ == "__main__":
    t = token(); body = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
    s, b = call(sys.argv[1], sys.argv[2], body, t); print(s, json.dumps(b, ensure_ascii=False) if os.environ.get("FULL") else json.dumps(b, ensure_ascii=False)[:3000])
