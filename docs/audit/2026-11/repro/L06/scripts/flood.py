import asyncio, time, sys, json, urllib.request
PORT=int(sys.argv[1]); N=int(sys.argv[2]); C=int(sys.argv[3])
async def worker(q, cnt):
    r,w=await asyncio.open_connection("127.0.0.1",PORT)
    while True:
        try: i=q.get_nowait()
        except asyncio.QueueEmpty: break
        w.write(f"GET /health?i={i} HTTP/1.1\r\nHost: x\r\n\r\n".encode()); await w.drain()
        await r.readuntil(b"\r\n\r\n"); 
        # read small JSON body via content-length
        cnt[0]+=1
        hdr=b""
    w.close()
async def body_reader(): pass
async def main():
    q=asyncio.Queue(); [q.put_nowait(i) for i in range(N)]; cnt=[0]; t=time.time()
    # simple: use http request with Connection: close semantics per request for robust parsing
    async def one(i):
        r,w=await asyncio.open_connection("127.0.0.1",PORT); w.write(f"GET /health?i={i} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode()); await w.drain(); await r.read(); w.close()
    sem=asyncio.Semaphore(C)
    async def lim(i):
        async with sem: await one(i)
    await asyncio.gather(*[lim(i) for i in range(N)])
    dt=time.time()-t; print(f"{N} req in {dt:.1f}s = {N/dt:.0f} rps")
asyncio.run(main())
def snap():
    d=json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/__tokiwa/health")); return d["shipper"]
print(snap())
