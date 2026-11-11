"""Capture JWTs, then: delete deluser, demote demoteuser admin->viewer, change pwchange's password (admin API)."""
import json, os, secrets, sys, httpx
BASE, PATH = sys.argv[1], sys.argv[2]
cr = json.load(open(PATH))
c = httpx.Client(base_url=BASE, timeout=30)
H = {"Authorization": "Bearer " + cr["admin"]["jwt"]}
for k in ("deluser", "demoteuser", "pwchange"):
    cr[k]["jwt_before"] = cr[k]["jwt"]
r = c.delete(f"/api/v1/users/{cr['deluser']['id']}", headers=H); print("delete deluser", r.status_code)
r = c.patch(f"/api/v1/users/{cr['demoteuser']['id']}", json={"role": "viewer"}, headers=H); print("demote", r.status_code, r.json().get("role"))
newpw = secrets.token_urlsafe(18)
r = c.patch(f"/api/v1/users/{cr['pwchange']['id']}", json={"password": newpw}, headers=H); print("pwchange", r.status_code)
cr["pwchange"]["password"] = newpw
for k in ("deluser", "demoteuser", "pwchange"):
    r = c.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + cr[k]["jwt_before"]})
    print("old jwt /auth/me", k, r.status_code, (r.json().get("role") if r.status_code == 200 else r.text[:60]))
r = c.get("/api/v1/users", headers={"Authorization": "Bearer " + cr["demoteuser"]["jwt_before"]}); print("demoted old jwt GET /users", r.status_code)
fd = os.open(PATH, os.O_WRONLY | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f: json.dump(cr, f)
