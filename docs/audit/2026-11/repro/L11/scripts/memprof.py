"""In-process: ingest N batches via ASGI, tracemalloc top growth, cProfile one batch."""
import asyncio, os, sys, time, tracemalloc, cProfile, pstats, io, gc, json
sys.path.insert(0, os.path.dirname(__file__))
import types
loadgen=types.SimpleNamespace()
_src=open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'loadgen.py')).read().split('async def worker')[0]
_g={}
exec(_src,_g)
loadgen.make=_g['make']
import httpx
from tokiwa.api.app import create_app
from tokiwa.schemas.events import Event
from tokiwa.pipeline.service import process_events
from tokiwa.bus import bus

ROT = "--rotate" in sys.argv
async def main():
    app = create_app(run_jobs=True)
    async with app.router.lifespan_context(app):
        evs = lambda: [Event.model_validate(e) for e in loadgen.make(100, ROT, 0)]
        for _ in range(5):
            await process_events(evs()); await bus.drain(30)
        gc.collect(); tracemalloc.start(25); s1 = tracemalloc.take_snapshot()
        t0 = time.perf_counter(); n = 40
        for _ in range(n):
            await process_events(evs())
        t_proc = time.perf_counter() - t0
        await bus.drain(60); t_all = time.perf_counter() - t0
        gc.collect(); s2 = tracemalloc.take_snapshot()
        print(f"rotate={ROT} {n*100} events: process_events {n*100/t_proc:.0f} ev/s, incl bus drain {n*100/t_all:.0f} ev/s; bus tasks pending after={len(bus._tasks)}")
        st = s2.compare_to(s1, "traceback")
        tot = sum(x.size_diff for x in st)
        print(f"net traced growth {tot/1e6:.1f} MB over {n*100} events = {tot/(n*100)/1e3:.1f} KB/event")
        for x in st[:6]:
            print(f"+{x.size_diff/1e6:.2f}MB count+{x.count_diff}")
            for fr in [f for f in x.traceback.format() if 'tokiwa' in f][-4:]:
                print("   ", fr.strip()[:160])
        tracemalloc.stop()
        pr = cProfile.Profile(); b = evs(); pr.enable(); await process_events(b); await bus.drain(30); pr.disable()
        s = io.StringIO(); pstats.Stats(pr, stream=s).sort_stats("cumulative").print_stats(r"tokiwa", 22); print(s.getvalue()[-6000:])
asyncio.run(main())
