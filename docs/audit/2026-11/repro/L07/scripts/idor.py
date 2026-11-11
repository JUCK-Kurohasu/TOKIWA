import json,sys,time,httpx
BASE,CR=sys.argv[1:3]; cr=json.load(open(CR)); c=httpx.Client(base_url=BASE,timeout=30)
h=lambda k:{"Authorization":"Bearer "+cr[k]["jwt"]}
r=c.post("/api/v1/copilot/conversations",json={"title":"secret analysis"},headers=h("analyst1")); print("create",r.status_code,r.text[:120]); cid=r.json()["id"]; time.sleep(0.2)
for k in ("viewer1","pwchange"):
    print(k,"GET",c.get(f"/api/v1/copilot/conversations/{cid}",headers=h(k)).status_code,"DEL",c.delete(f"/api/v1/copilot/conversations/{cid}",headers=h(k)).status_code,
      "POST msg",c.post(f"/api/v1/copilot/conversations/{cid}/messages",json={"content":"hi"},headers=h(k)).status_code,
      "list all",len(c.get("/api/v1/copilot/conversations",params={"all":"true"},headers=h(k)).json()))
