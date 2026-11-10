import json,sys,time,httpx,statistics
BASE,CR=sys.argv[1:3]; cr=json.load(open(CR)); c=httpx.Client(base_url=BASE,timeout=30)
H={"Authorization":"Bearer "+cr["admin"]["jwt"]}
r=c.delete(f"/api/v1/tokens/{cr['tok-revoked']['id']}",headers=H); print("revoke",r.status_code)
T={"X-Tokiwa-Token":cr["tok-revoked"]["token"]}
print("revoked gate/policy",c.get("/api/v1/gate/policy",headers=T).status_code)
print("revoked ingest",c.post("/api/v1/ingest/events",headers=T,json=[]).status_code)
# login brute force
t0=time.time(); codes={}
for i in range(200):
    r=c.post("/api/v1/auth/login",json={"username":"admin","password":f"wrong{i}xxxxx"}); codes[r.status_code]=codes.get(r.status_code,0)+1
print("200 wrong logins",codes,"secs",round(time.time()-t0,1))
r=c.post("/api/v1/auth/login",json={"username":"admin","password":cr["admin"]["password"]}); print("correct after 200 wrong",r.status_code)
# enumeration
def tm(u):
    ts=[]
    for i in range(15):
        t=time.perf_counter(); r=c.post("/api/v1/auth/login",json={"username":u,"password":"wrongpassword1"}); ts.append(time.perf_counter()-t)
    return statistics.median(ts)*1000, r.status_code, r.text[:80]
print("existing",tm("admin")); print("nonexist",tm("nosuchuser_zz"))
print("setup again",c.post("/api/v1/auth/setup",json={"username":"x2","password":"abcdefghijkl"}).status_code)
print("status",c.get("/api/v1/auth/status").text)
