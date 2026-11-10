"""Offline repro: one future-dated event poisons SessionTracker.max_event_ts -> sessions expire on every drain."""
import asyncio, copy, sys
from datetime import timedelta
from tokiwa.eval.dataset import generate_events
from tokiwa.eval.harness import make_batches
from tokiwa.aidetect.sessions import SessionTracker
from tokiwa.schemas.events import Event, EventKind, Endpoint, HttpInfo

def run(events, poison_offset_s=None, poison_naive=False):
    tr = SessionTracker()
    evs = sorted((copy.deepcopy(e) for e in events), key=lambda e: e.timestamp)
    first = evs[0].timestamp
    if poison_offset_s is not None:
        p = Event(timestamp=first + timedelta(seconds=poison_offset_s), kind=EventKind.HTTP, dataset="gate.http",
                  source=Endpoint(ip="10.9.9.9"), http=HttpInfo(method="GET", path="/health", status=200,
                  user_agent="kube-probe/1.30"))
        tr.observe_batch([p]); tr.drain_dirty()
    sess = {}
    for b in make_batches(evs, window_seconds=1.0, max_size=100):
        tr.observe_batch(b)
        tr.drain_dirty()   # production flushes >= every 1 s (sessionizer.flush -> drain_dirty -> expire_idle)
        for e in b:
            s = tr.get(e.session_id)
            sess.setdefault(e.session_id, [0, 0.0, "?"])
            sess[e.session_id][0] += 1
            if s is not None:
                sess[e.session_id][1] = max(sess[e.session_id][1], s.ai_score)
                sess[e.session_id][2] = str(s.classification)
    return tr, sess

async def main():
    evs = await generate_events({"ai_agent": 1}, seed=int(sys.argv[1]) if len(sys.argv) > 1 else 3, canary=False)
    for e in evs: e.labels = {}
    print("agent events:", len(evs), "span_s:", round((max(e.timestamp for e in evs)-min(e.timestamp for e in evs)).total_seconds()))
    for label, off in (("no poison", None), ("sensor clock +31min (1 event)", 31*60), ("future +1 day (1 event)", 86400), ("future year+70 (1 event)", 70*365*86400)):
        tr, sess = run(evs, off)
        agent = {k: v for k, v in sess.items()}
        peak = max(v[1] for v in agent.values()); n5 = sum(1 for v in agent.values() if v[0] >= 5)
        cls = sorted({v[2] for v in agent.values()})
        print(f"{label:34s} pipeline_sessions={len(agent):4d} sessions>=5req={n5:3d} peak_ai={peak:.3f} classes={cls} expired={tr.stats['expired']}")

asyncio.run(main())
