"""Create admin/analyst/viewer users + scoped API tokens on the lane server; store creds in a 0600 JSON file."""
import json, os, secrets, sys
import httpx

BASE = sys.argv[1]
OUT = sys.argv[2]
c = httpx.Client(base_url=BASE, timeout=30)
creds = {}
pw = lambda: secrets.token_urlsafe(18)
admin_pw = pw()
r = c.post("/api/v1/auth/setup", json={"username": "admin", "password": admin_pw})
print("setup", r.status_code)
r.raise_for_status()
creds["admin"] = {"username": "admin", "password": admin_pw, "jwt": r.json()["access_token"], "id": r.json()["user"]["id"]}
H = {"Authorization": f"Bearer {creds['admin']['jwt']}"}
for name, role in [("analyst1", "analyst"), ("viewer1", "viewer"), ("deluser", "analyst"), ("demoteuser", "admin"), ("pwchange", "analyst")]:
    p = pw()
    r = c.post("/api/v1/users", json={"username": name, "password": p, "role": role}, headers=H)
    print("create", name, r.status_code)
    uid = r.json()["id"]
    r2 = c.post("/api/v1/auth/login", json={"username": name, "password": p})
    print("login", name, r2.status_code)
    creds[name] = {"username": name, "password": p, "jwt": r2.json()["access_token"], "id": uid, "role": role}
for name, scopes in [("tok-ingest", ["ingest"]), ("tok-gate", ["gate"]), ("tok-read", ["read"]), ("tok-revoked", ["ingest", "gate"])]:
    r = c.post("/api/v1/tokens", json={"name": name, "scopes": scopes}, headers=H)
    print("token", name, r.status_code)
    creds[name] = {"token": r.json()["token"], "id": r.json()["id"], "scopes": scopes}
fd = os.open(OUT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(creds, f)
print("saved", OUT)
