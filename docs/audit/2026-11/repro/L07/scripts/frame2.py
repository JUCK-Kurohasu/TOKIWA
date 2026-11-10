import json,sys,time,httpx
BASE,CR=sys.argv[1:3]; cr=json.load(open(CR)); c=httpx.Client(base_url=BASE,timeout=120)
T={"X-Tokiwa-Token":cr["tok-ingest"]["token"]}; H={"Authorization":"Bearer "+cr["admin"]["jwt"]}; G={"X-Tokiwa-Token":cr["tok-gate"]["token"]}
V="198.51.100.23"
acts=c.get("/api/v1/response/actions",params={"limit":100},headers=H).json(); acts=acts.get("items",acts)
b=[a for a in acts if a["action_type"]=="block_ip" and V in json.dumps(a)][0]
print("block target",b.get("target"),"rationale",str(b.get("rationale"))[:150])
r=c.post(f"/api/v1/response/actions/{b['id']}/approve",json={},headers=H); print("approve",r.status_code,r.json().get("status") if r.status_code<300 else r.text[:200])
time.sleep(1)
pol=c.get("/api/v1/gate/policy",headers=G).json(); print("victim in gate blocked list", V in json.dumps(pol.get("blocked",pol)))
ev=c.get("/api/v1/events",params={"source_ip":V,"limit":1},headers=H).json(); ev=ev.get("items",ev); print("stored sensor_id",ev[0].get("sensor_id") if ev else None)
# size test
big="A"*(8*1024*1024)
t=time.time(); r=c.post("/api/v1/ingest/events",json={"events":[{"kind":"http","dataset":"gate.http","source":{"ip":"192.0.2.9"},"message":big,"http":{"method":"GET","path":"/x","user_agent":big[:2*1024*1024]}}]},headers=T)
print("8MB message ingest",r.status_code,round(time.time()-t,2),"s")
ev=c.get("/api/v1/events",params={"source_ip":"192.0.2.9","limit":1},headers=H).json(); ev=ev.get("items",ev)
print("stored message len",len(ev[0].get("message") or "") if ev else None, "ua len", len((ev[0].get("http") or {}).get("user_agent") or "") if ev else None)
import os; print("db size MB", round(os.path.getsize(sys.argv[3])/1e6,1))
