"""Does one future-dated event (sensor clock skew) break sessionization for everyone?"""
from datetime import UTC, datetime, timedelta
from tokiwa.aidetect.sessions import SessionTracker
from tokiwa.schemas.events import Event, EventKind, HttpInfo, Endpoint

def ev(ip, ts, path="/api/items"):
    return Event(kind=EventKind.HTTP, dataset="gate", timestamp=ts, source=Endpoint(ip=ip),
                 http=HttpInfo(method="GET", path=path, status=200, user_agent="python-httpx/0.27"))

for poison in (False, True):
    t = SessionTracker(idle_timeout_s=1800)
    now = datetime.now(UTC)
    ids = set()
    if poison:
        t.observe_batch([ev("198.51.100.9", now + timedelta(days=1))])  # one skewed sensor event
    for i in range(20):
        e = ev("203.0.113.5", now + timedelta(seconds=2 * i), f"/api/items/{i}")
        t.observe_batch([e]); t.drain_dirty()   # drain = what the 1 s / 5 s flush does
        ids.add(e.session_id)
    print(f"poison={poison}: 20 requests from one client over 40 s -> {len(ids)} session(s); max_event_ts={datetime.fromtimestamp(t.max_event_ts, UTC):%Y-%m-%d %H:%M}")
