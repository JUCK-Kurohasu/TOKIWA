"""mode=hdr: N conns trickling header bytes; mode=body: N POSTs trickling body. Then probe normal GET latency."""
import asyncio, sys, time
PORT=int(sys.argv[1]); MODE=sys.argv[2]; N=int(sys.argv[3]); DUR=float(sys.argv[4])
alive=0; closed_at=[]
async def slow(i):
    global alive
    t0=time.time()
    try:
        r,w=await asyncio.open_connection("127.0.0.1",PORT)
        if MODE=="hdr": w.write(b"GET / HTTP/1.1\r\nHost: x\r\n")
        else: w.write(b"POST /slow HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
        await w.drain(); alive+=1
        while time.time()-t0<DUR:
            await asyncio.sleep(5)
            w.write(b"X-a: b\r\n" if MODE=="hdr" else b"a"); await w.drain()
            if r.at_eof(): raise ConnectionError
        w.close()
    except Exception: closed_at.append(round(time.time()-t0,1))
    finally: alive-=1
async def probe():
    await asyncio.sleep(8)
    for k in range(3):
        t=time.time()
        try:
            r,w=await asyncio.open_connection("127.0.0.1",PORT); w.write(b"GET /probe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); await w.drain()
            line=await asyncio.wait_for(r.readline(),timeout=45); print("probe",k,line[:30],round(time.time()-t,2),"s alive",alive,flush=True)
        except Exception as e: print("probe",k,"ERR",type(e).__name__,round(time.time()-t,2),flush=True)
        await asyncio.sleep(5)
async def main():
    await asyncio.gather(*[slow(i) for i in range(N)], probe())
    print("closed early:",len(closed_at), sorted(closed_at)[:5], sorted(closed_at)[-3:])
asyncio.run(main())
