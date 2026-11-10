"""Ingest load generator: POST /api/v1/ingest/events with realistic gate.http events (lab-mini templates).

usage: loadgen.py URL TOKENFILE --batch 100 --conc 1 --seconds 30 [--rotate] [--maxevents N] [--pid PID]
"""
import argparse, asyncio, json, random, time, uuid, os, statistics
from datetime import datetime, UTC, timedelta
import httpx

TPL = [json.loads(l) for l in open("/home/user/TOKIWA/eval/datasets/lab-mini.jsonl")]
for t in TPL:
    t.pop("labels", None)
UAS = ["python-httpx/0.27.%d" % i for i in range(50)] + ["Mozilla/5.0 (X11; Linux x86_64) Chrome/%d.0" % i for i in range(100, 140)]

def rss(pid):
    try:
        for l in open(f"/proc/{pid}/status"):
            if l.startswith("VmRSS"):
                return int(l.split()[1]) // 1024
    except Exception:
        return -1

def make(n, rotate, seq):
    out = []
    now = datetime.now(UTC)
    for i in range(n):
        e = json.loads(json.dumps(random.choice(TPL)))
        e["id"] = uuid.uuid4().hex
        e["timestamp"] = (now + timedelta(microseconds=i)).isoformat()
        e["sensor_id"] = "loadgen"
        if rotate:
            e["source"] = {"ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}", "port": 40000}
            ua = random.choice(UAS) + f" r{random.randint(0, 10**6)}"
            e["http"]["user_agent"] = ua
            e["http"].setdefault("headers", {})["user-agent"] = ua
            # header-name randomisation (changes the client fingerprint)
            e["http"]["headers"][f"x-r{random.randint(0, 999)}"] = "1"
            e["http"]["header_order"] = list(e["http"]["headers"].keys())
        out.append(e)
    return out

async def worker(client, url, hdr, args, lat, cnt, stop, errs):
    seq = 0
    while time.monotonic() < stop and (args.maxevents == 0 or cnt[0] < args.maxevents):
        body = {"events": make(args.batch, args.rotate, seq)}
        t0 = time.perf_counter()
        try:
            r = await client.post(url, json=body, headers=hdr)
            dt = time.perf_counter() - t0
            if r.status_code == 200:
                lat.append(dt); cnt[0] += args.batch; cnt[1] += r.json().get("alerts", 0)
            else:
                errs.append(f"{r.status_code}:{r.text[:120]}")
        except Exception as ex:
            errs.append(repr(ex)[:120])
        seq += 1

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url"); ap.add_argument("tokenfile")
    ap.add_argument("--batch", type=int, default=100); ap.add_argument("--conc", type=int, default=1)
    ap.add_argument("--seconds", type=float, default=30); ap.add_argument("--rotate", action="store_true")
    ap.add_argument("--maxevents", type=int, default=0); ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--label", default="")
    args = ap.parse_args()
    tok = open(args.tokenfile).read().strip()
    hdr = {"Authorization": f"Bearer {tok}"}
    url = args.url.rstrip("/") + "/api/v1/ingest/events"
    lat, cnt, errs = [], [0, 0], []
    r0 = rss(args.pid) if args.pid else -1
    t0 = time.monotonic(); stop = t0 + args.seconds
    async with httpx.AsyncClient(timeout=120) as c:
        await asyncio.gather(*[worker(c, url, hdr, args, lat, cnt, stop, errs) for _ in range(args.conc)])
    el = time.monotonic() - t0
    q = sorted(lat)
    pct = lambda p: q[min(len(q) - 1, int(p * len(q)))] if q else float("nan")
    res = dict(label=args.label, batch=args.batch, conc=args.conc, rotate=args.rotate, events=cnt[0], alerts_created=cnt[1],
               seconds=round(el, 1), eps=round(cnt[0] / el, 1), req=len(lat), p50=round(pct(.5), 3), p95=round(pct(.95), 3),
               p99=round(pct(.99), 3), max=round(q[-1], 3) if q else None, errors=len(errs), err_sample=errs[:3],
               rss_before_mb=r0, rss_after_mb=rss(args.pid) if args.pid else -1, loadavg=os.getloadavg()[0])
    print(json.dumps(res))

asyncio.run(main())
