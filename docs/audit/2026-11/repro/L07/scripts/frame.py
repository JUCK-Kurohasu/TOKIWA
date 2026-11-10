import json,sys,time,httpx,random
BASE,CR=sys.argv[1:3]; cr=json.load(open(CR)); c=httpx.Client(base_url=BASE,timeout=60)
T={"X-Tokiwa-Token":cr["tok-ingest"]["token"]}; H={"Authorization":"Bearer "+cr["admin"]["jwt"]}
VICTIM="198.51.100.23"
UA="python-requests/2.31.0"
paths=["/.env","/backup.sql","/.git/config","/admin","/api/users?id=1' OR '1'='1","/wp-login.php","/phpmyadmin/","/etc/passwd","/api/v1/users/1","/api/v1/users/2","/server-status","/../../etc/passwd","/api/internal/openapi.json"]
ev=[]
now=time.time()
for i,p in enumerate(paths*4):
    path,_,q=p.partition("?")
    ev.append({"kind":"http","dataset":"gate.http","sensor_id":"gate-prod-1","timestamp":time.strftime("%Y-%m-%dT%H:%M:%S",time.gmtime(now-60+i))+"Z",
      "source":{"ip":VICTIM,"port":40000+i},"destination":{"ip":"10.0.0.5","port":443},
      "http":{"method":"GET","path":path,"query":q or None,"user_agent":UA,"status":404,"headers":{"user-agent":UA}}})
r=c.post("/api/v1/ingest/events",json={"events":ev},headers=T); print("ingest",r.status_code,r.text[:300])
time.sleep(4)
al=c.get("/api/v1/alerts",params={"limit":100},headers=H).json(); items=al.get("items",al)
mine=[a for a in items if VICTIM in json.dumps(a)]
print("alerts for victim",len(mine)); [print(" ",a.get("severity"),a.get("title"),a.get("detector") or a.get("rule_id")) for a in mine[:12]]
for ep in ("/api/v1/incidents","/api/v1/response/actions"):
    d=c.get(ep,params={"limit":100},headers=H).json(); it=d.get("items",d)
    m=[x for x in it if VICTIM in json.dumps(x)]
    print(ep,len(m)); [print(" ",json.dumps({k:x.get(k) for k in ("severity","title","action_type","status","params","proposed_by")},ensure_ascii=False)[:300]) for x in m[:5]]
