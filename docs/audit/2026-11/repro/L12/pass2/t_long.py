import json, os, sys
from tokiwa.sensors.logtail import FileTailer, LogSource
from tokiwa.sensors.caddy import CaddyJsonParser
from tokiwa.sensors.normalize import ParseContext
p=os.path.join(os.path.dirname(os.path.abspath(__file__)),"caddy_access.log")
open(p,"w").close()
src=LogSource(FileTailer(p,start_at="beginning"),CaddyJsonParser(ParseContext(sensor_id="t")))
src.poll_sync()
def line(path, pad_n):
    rec={"level":"info","ts":1729591200.12,"logger":"http.log.access","msg":"handled request",
     "request":{"remote_ip":"203.0.113.7","client_ip":"203.0.113.7","proto":"HTTP/1.1","method":"GET","host":"app","uri":path,
     "headers":{"User-Agent":["python-requests/2.31"],"X-Pad":['"'*pad_n]}},"status":200,"size":10}
    return json.dumps(rec)+"\n"
with open(p,"a") as f:
    f.write(line("/ok-before",10))
    l=line("/api/users?id=1%27%20UNION%20SELECT%20password%20FROM%20users--",600_000)  # 600k quotes -> 1.2MB escaped
    print("attack line bytes:",len(l)); f.write(l)
    f.write(line("/ok-after",10))
evs=src.poll_sync()
print("events:",[e.http.path+"?"+(e.http.query or "") for e in evs],"errors:",src.errors,"lines:",src.lines)
