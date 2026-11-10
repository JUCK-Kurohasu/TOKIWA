"""LRU eviction: flood of N one-request sessions (distinct IP) after the agent's recon phase evicts its live session."""
import asyncio, copy, sys, tracemalloc
from datetime import timedelta
from tokiwa.eval.dataset import generate_events
from tokiwa.eval.harness import make_batches
from tokiwa.aidetect.sessions import SessionTracker
from tokiwa.schemas.events import Event, EventKind, Endpoint, HttpInfo

def flood(t0, n):
    return [Event(timestamp=t0 + timedelta(milliseconds=i % 900), kind=EventKind.HTTP, dataset="gate.http",
                  source=Endpoint(ip=f"10.{(i>>16)&255}.{(i>>8)&255}.{i&255}"),
                  http=HttpInfo(method="GET", path="/", status=200, user_agent="Mozilla/5.0 (compatible; x)"))
            for i in range(n)]

def run(evs, n_flood, at_frac):
    tr = SessionTracker()
    evs = sorted((copy.deepcopy(e) for e in evs), key=lambda e: e.timestamp)
    cut = int(len(evs) * at_frac)
    agent_ids = set(); per = {}
    for i, b in enumerate(make_batches(evs, window_seconds=1.0, max_size=100)):
        if n_flood and b[0].timestamp >= evs[cut].timestamp and not getattr(run, "_done", False):
            for fb in [flood(b[0].timestamp, n_flood)[k:k+500] for k in range(0, n_flood, 500)]:
                tr.observe_batch(fb)
            run._done = True
        tr.observe_batch(b); tr.drain_dirty()
        for e in b:
            s = tr.get(e.session_id)
            if s: per[e.session_id] = (per.get(e.session_id, (0, 0, ""))[0] + 1, max(per.get(e.session_id, (0, 0.0, ""))[1], s.ai_score), str(s.classification))
    run._done = False
    return tr, per

async def main():
    evs = await generate_events({"ai_agent": 1}, seed=3, canary=False)
    for e in evs: e.labels = {}
    for n in (0, 4000, 4200):
        tracemalloc.start()
        tr, per = run(evs, n, 0.3)
        cur, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
        print(f"flood={n} agent_sessions={len(per)} " + " ; ".join(f"{c}req peak={p:.3f} {k}" for c, p, k in per.values()) + f" | evicted={tr.stats['evicted']} live={len(tr)} pending={len(tr._pending)} mem_peak={peak/1e6:.1f}MB")
asyncio.run(main())
