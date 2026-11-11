import json,sys,asyncio,httpx,secrets
BASE,CR=sys.argv[1:3]; cr=json.load(open(CR)); H={"Authorization":"Bearer "+cr["admin"]["jwt"]}
c=httpx.Client(base_url=BASE,timeout=30)
for p in ["/api/v1/events?since=99999-01-01","/api/v1/events?q=%25%25%25_","/api/v1/alerts?q=%25"]:
    r=httpx.get(BASE+p,headers=H); print(r.status_code,p,r.text[:160].replace("\n"," "))
r=c.post("/api/v1/users",content=b'{"username":',headers={**H,"content-type":"application/json"}); print("malformed json",r.status_code,r.text[:200])
# concurrent admin demotion race: admin creates 2nd admin; then both demoted concurrently; check admin count
async def main():
    n="adm"+secrets.token_hex(2); pw="Abcdefgh12345!"
    async with httpx.AsyncClient(base_url=BASE,timeout=30) as a:
        # demote all admins except 'admin' first so we have exactly admin + new
        us=(await a.get("/api/v1/users",headers=H)).json()
        for u in us:
            if u["role"]=="admin" and u["username"]!="admin": await a.patch(f"/api/v1/users/{u['id']}",json={"role":"viewer"},headers=H)
        u2=(await a.post("/api/v1/users",json={"username":n,"password":pw,"role":"admin"},headers=H)).json()
        await asyncio.sleep(0.2)
        j2=(await a.post("/api/v1/auth/login",json={"username":n,"password":pw})).json()["access_token"]
        H2={"Authorization":"Bearer "+j2}
        rs=await asyncio.gather(a.patch(f"/api/v1/users/{u2['id']}",json={"role":"viewer"},headers=H), a.patch(f"/api/v1/users/{cr['admin']['id']}",json={"role":"viewer"},headers=H2))
        print("concurrent demote", [r.status_code for r in rs])
        await asyncio.sleep(0.5)
        r=await a.post("/api/v1/auth/login",json={"username":"admin","password":cr["admin"]["password"]}); print("admin role now", r.json()["user"]["role"])
        r=await a.post("/api/v1/auth/login",json={"username":n,"password":pw}); print(n,"role now", r.json()["user"]["role"])
        print("setup available", (await a.get("/api/v1/auth/status")).json())
asyncio.run(main())
