"""LLM-orchestrated stock-tool chain (HexStrike/PentAGI/GTG-1002 shape): one IP, sequential tools, own default UA, LLM think gaps between phases."""
import sys, random, json
sys.argv=["x"]
exec(open("docs/audit/2026-11/repro/L02/scripts/repro_sessions.py").read().split("rng = random.Random(7)\nfixed_ua")[0])
rng=random.Random(3); IP="203.0.113.50"; t=T0; out=[]
def req(ua,path,q=None,st=404,gap=0.1):
    global t
    t=t+timedelta(seconds=gap); out.append(ev(t,IP,ua,path,q,st))
phases=[("Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))",[f"/{w}" for w in ["admin","login",".git/config","wp-login.php","actuator/env","api/v1/users","backup.zip",".env","phpinfo.php","server-status"]*4],0.15),
 ("Fuzz Faster U Fool v2.1.0",[f"/api/{w}" for w in ["users","orders","admin","debug","internal","export","v2","health","metrics","keys"]*5],0.05),
 ("sqlmap/1.8.11#stable (https://sqlmap.org)",None,0.3)]
for ua,paths,gap in phases:
    t+=timedelta(seconds=rng.uniform(8,40))   # LLM reads tool output, decides next tool
    if paths:
        for p in paths: req(ua,p,None,404 if rng.random()<.8 else 200,gap)
    else:
        for i in range(30): req(ua,"/api/v1/search",f"q=a{'%27' if i%2 else ''}{i}",500 if i%3==0 else 200,gap)
tr=SessionTracker(); tr.observe_batch(out)
for s in tr.sessions():
    print(json.dumps({"ua":s.user_agent[:30] if hasattr(s,"user_agent") else "", "n":s.request_count,"cls":str(s.classification),"ai":s.ai_score,"ind":[i["key"] for i in s.indicators[:4]]},ensure_ascii=False))
