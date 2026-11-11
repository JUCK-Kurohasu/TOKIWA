import json,sys,httpx
BASE,CR=sys.argv[1:3]; cr=json.load(open(CR)); c=httpx.Client(base_url=BASE,timeout=30)
H={"Authorization":"Bearer "+cr["admin"]["jwt"]}
import secrets;R=secrets.token_hex(3)
res={"tok_after_revoke":[], "user_after_delete":[], "role_after_demote":[]}
for i in range(10):
    t=c.post("/api/v1/tokens",json={"name":f"r{i}","scopes":["gate"]},headers=H).json()
    c.delete(f"/api/v1/tokens/{t['id']}",headers=H)
    res["tok_after_revoke"].append(c.get("/api/v1/gate/policy",headers={"X-Tokiwa-Token":t["token"]}).status_code)
    u=c.post("/api/v1/users",json={"username":f"ru{i}{R}","password":"Abcdefgh12345","role":"admin"},headers=H).json()
    lr=c.post("/api/v1/auth/login",json={"username":f"ru{i}{R}","password":"Abcdefgh12345"}); res.setdefault("login_after_create",[]).append(lr.status_code)
    import time
    if lr.status_code!=200: time.sleep(0.3); lr=c.post("/api/v1/auth/login",json={"username":f"ru{i}{R}","password":"Abcdefgh12345"})
    j=lr.json()["access_token"]
    c.patch(f"/api/v1/users/{u['id']}",json={"role":"viewer"},headers=H)
    res["role_after_demote"].append(c.get("/api/v1/users",headers={"Authorization":"Bearer "+j}).status_code)
    c.delete(f"/api/v1/users/{u['id']}",headers=H)
    res["user_after_delete"].append(c.get("/api/v1/auth/me",headers={"Authorization":"Bearer "+j}).status_code)
print(res)
