import asyncio, os, sys, logging, sqlite3, collections as C
from pathlib import Path
MY=Path(__file__).resolve().parent; sys.path.insert(0,str(MY))
os.environ.update({"TOKIWA_ENV":"test","TOKIWA_CONFIG":str(MY/"none.yaml"),"TOKIWA_LLM__PROVIDER":"mock","TOKIWA_DETECTION__SIGMA_RULE_DIRS":'["/home/user/TOKIWA/rules/sigma"]'})
logging.disable(logging.WARNING)
from tokiwa.eval.harness import replay, ReplayOptions
import corpus
evs=[e for e in corpus.build(1) if corpus.SCEN[e.source.ip]=="text_user"]
excl={"webhook_url_setting","chat_ai_question"}
for name,sub,ov in [("all",evs,{}),("clean13",[e for e in evs if e.labels.get("case") not in excl],{}),
    ("clean13_native_off",[e for e in evs if e.labels.get("case") not in excl],{d:False for d in ["web.log4shell","web.xss","web.sqli","web.cmd_injection","web.path_traversal","web.ssrf","web.deserialization","ai.natural_language_payload"]})]:
    out=MY/f"tune_{name}"; r=asyncio.run(replay(sub,out,ReplayOptions(llm="mock",detector_overrides=ov)))
    rows=sqlite3.connect(out/"eval.db").execute("select action_type from response_actions").fetchall()
    print(name,len(sub),"alerts",len(r.alerts),dict(C.Counter(str(a['severity']) for a in r.alerts)),"inc",[str(i['severity']) for i in r.incidents],"prop",[x[0] for x in rows])
    print("   rules", sorted(C.Counter(a['rule_id'][:22] for a in r.alerts).items()))
