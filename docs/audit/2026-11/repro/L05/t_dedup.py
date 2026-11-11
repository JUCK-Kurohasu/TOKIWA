import sys, asyncio, os
sys.path.insert(0, sys.argv[1])
os.environ["TOKIWA_DATABASE__URL"] = f"sqlite+aiosqlite:///{sys.argv[1]}/data/dd.db"
from harness import *
from tokiwa.db.session import init_engine, create_all, session_scope
from tokiwa import bus as busmod
seen = []
async def main():
    init_engine(os.environ["TOKIWA_DATABASE__URL"]); await create_all()
    from tokiwa.bus import bus
    bus.subscribe("alert.created", lambda a: seen.append(("created", a.rule_id, a.severity)) or asyncio.sleep(0))
    bus.subscribe("alert.updated", lambda a: seen.append(("updated", a.rule_id, a.severity)) or asyncio.sleep(0))
    ENGINE.ctx = DetectionContext(S)
    steps = [("probe", "/api/items?id=" + "1'"),
             ("boolean", "/api/items?id=1%20AND%201=1--"),
             ("union dump", "/api/items?id=-1%20UNION%20SELECT%20username,password%20FROM%20users--"),
             ("stacked/xp_cmdshell", "/api/items?id=1;EXEC%20xp_cmdshell('whoami')--"),
             ("time based", "/api/items?id=1%20AND%20SLEEP(5)--")]
    for name, t in steps:
        drafts = await ENGINE.run([direct_event(t)])
        async with session_scope() as s:
            c, u = await ENGINE.persist(s, drafts)
        await ENGINE.publish(c, u)
        await asyncio.sleep(0.05)
        print(name, "->", [(d.rule_id, d.severity.value if hasattr(d.severity,'value') else d.severity, d.title[:60]) for d in drafts if d.rule_id.startswith("web.")], "| created", [a.rule_id for a in c], "updated", [(a.rule_id, a.severity, a.count, a.title[:50]) for a in u if a.rule_id.startswith("web.")])
    print("bus:", [x for x in seen if x[1].startswith("web.")])
asyncio.run(main())
