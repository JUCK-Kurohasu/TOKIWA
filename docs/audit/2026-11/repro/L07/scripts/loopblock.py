import asyncio,httpx,time,sys
BASE=sys.argv[1]
async def health(a,out):
    for _ in range(20):
        t=time.perf_counter(); await a.get("/api/v1/health"); out.append((time.perf_counter()-t)*1000); await asyncio.sleep(0.05)
async def logins(a,n):
    for i in range(n): await a.post("/api/v1/auth/login",json={"username":"admin","password":"wrongpass%d"%i})
async def main():
    async with httpx.AsyncClient(base_url=BASE,timeout=60,limits=httpx.Limits(max_connections=50)) as a:
        base=[];await health(a,base)
        out=[];t=time.time()
        await asyncio.gather(health(a,out),*[logins(a,15) for _ in range(16)])
        print("health ms idle p50/max",sorted(base)[10],round(max(base)),"under 16 concurrent login streams p50/max",round(sorted(out)[10]),round(max(out)),"total",round(time.time()-t,1),"s for 240 logins")
asyncio.run(main())
