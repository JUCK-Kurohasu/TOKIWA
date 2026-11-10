import json,sys,time,asyncio,httpx,secrets
BASE,CR=sys.argv[1:3]; cr=json.load(open(CR)); H={"Authorization":"Bearer "+cr["admin"]["jwt"]}
c=httpx.Client(base_url=BASE,timeout=30)
for d in (0,0.005,0.02,0.1):
    ok=0
    for i in range(10):
        t=c.post("/api/v1/tokens",json={"name":"w","scopes":["gate"]},headers=H).json(); c.delete(f"/api/v1/tokens/{t['id']}",headers=H); time.sleep(d)
        ok+= c.get("/api/v1/gate/policy",headers={"X-Tokiwa-Token":t["token"]}).status_code==200
    print("delay",d,"revoked-token-accepted",ok,"/10")
async def main():
    name="dup"+secrets.token_hex(3)
    async with httpx.AsyncClient(base_url=BASE,timeout=30) as a:
        rs=await asyncio.gather(*[a.post("/api/v1/users",json={"username":name,"password":"Abcdefgh12345","role":"viewer"},headers=H) for _ in range(6)])
        print("concurrent create same user",[r.status_code for r in rs])
        await asyncio.sleep(1)
        us=(await a.get("/api/v1/users",headers=H)).json()
        print("rows with that name", sum(1 for u in us if u["username"]==name))
asyncio.run(main())
