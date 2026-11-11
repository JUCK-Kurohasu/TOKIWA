import json, urllib.request, sys
M="docs/audit/2026-11/repro/L10/pass2/run"
tok=open(M+"/ingest.token").read().strip()
RLO="‮"; PDF="‬"; ZW="​"
def ev(ip, path, ua, q=None, body=None, method="GET", status=404):
    return {"kind":"http","dataset":"gate.http","sensor_id":"l10",
            "source":{"ip":ip},"http":{"method":method,"path":path,"query":q,"user_agent":ua,
            "headers":{"user-agent":ua,"x-note":"<b>hdr</b>"+RLO+"txt"},"request_body":body,"status":status}}
evs=[]
# bidi: displayed path looks like ".../exe.pdf" etc
evs.append(ev("198.51.100.7","/download/invoice"+RLO+"fdp.exe","curl/8.5"))
# zero-width: '/.e​nv' looks like '/.env'
evs.append(ev("198.51.100.7","/.e"+ZW+"nv","curl/8.5"))
# UA with RLO so that IP-looking text reversed
evs.append(ev("198.51.100.8","/.env","python-requests/2.32 "+RLO+"7.001.15.891 ← benign scanner"+PDF))
# markup everywhere + sqli to trigger alert
evs.append(ev("198.51.100.9","/api/users","<img src=x onerror=alert(1)>",q="id=1' OR '1'='1 <script>alert(2)</script>",body='{"x":"<svg onload=alert(3)>"}',method="POST"))
for p in ["/.git/config","/wp-login.php","/.env","/etc/passwd","/admin"]:
    evs.append(ev("198.51.100.10",p,"Mozilla/5.0 "+RLO+"suoicilam ton"+PDF))
req=urllib.request.Request("http://127.0.0.1:22000/api/v1/ingest/events",data=json.dumps({"events":evs}).encode(),
    headers={"Content-Type":"application/json","Authorization":"Bearer "+tok})
print(urllib.request.urlopen(req).read().decode())
