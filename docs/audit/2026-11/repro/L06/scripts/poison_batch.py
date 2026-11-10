"""Gate shipper head-of-line test: ingest answers 500 for any batch containing a NUL (as PostgreSQL would)."""
import asyncio, httpx, time
from tokiwa.gate.shipper import EventShipper
from tokiwa.schemas.events import Event, EventKind, HttpInfo
delivered = []
def handler(req: httpx.Request) -> httpx.Response:
    if b"\\u0000" in req.content: return httpx.Response(500)
    import json; delivered.extend(json.loads(req.content)["events"]); return httpx.Response(200, json={})
async def main():
    c = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    s = EventShipper(c, "http://srv", "t", batch_size=100, flush_interval=0.05, max_queue=10000, max_backoff=0.2)
    mk = lambda p: Event(kind=EventKind.HTTP, dataset="gate.http", http=HttpInfo(method="GET", path=p))
    s.submit(mk("/poison\x00"))
    for i in range(3000): s.submit(mk(f"/attack-{i}"))
    task = asyncio.create_task(s.run()); await asyncio.sleep(3); task.cancel()
    print("submitted 3001, delivered", len(delivered), "queued", len(s), "stats", {k: v for k, v in s.snapshot().items() if k in ("failed_attempts","dropped_overflow","last_error")})
asyncio.run(main())
