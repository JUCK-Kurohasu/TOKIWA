import json, os, sys, httpx
BASE, PATH = sys.argv[1], sys.argv[2]
creds = json.load(open(PATH))
c = httpx.Client(base_url=BASE, timeout=30)
for k, v in creds.items():
    if "password" in v:
        r = c.post("/api/v1/auth/login", json={"username": v["username"], "password": v["password"]})
        print(k, r.status_code)
        if r.status_code == 200:
            v["jwt"] = r.json()["access_token"]
fd = os.open(PATH, os.O_WRONLY | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(creds, f)
