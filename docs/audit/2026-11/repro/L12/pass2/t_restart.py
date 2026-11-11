import json, os
from tokiwa.config import AgentSettings
from tokiwa.sensors.agent import build_sources
from tokiwa.sensors.normalize import ParseContext
p=os.path.join(os.path.dirname(os.path.abspath(__file__)),"nginx_access.log")
def L(path): return json.dumps({"time_iso8601":"2026-11-11T00:00:00+00:00","remote_addr":"203.0.113.9","request_method":"GET","request_uri":path,"status":"200"})+"\n"
open(p,"w").write(L("/before-start"))
cfg=AgentSettings(host_sensor=False,nginx_json_logs=[p])
ctx=ParseContext(sensor_id="t")
s1=build_sources(cfg,ctx,cfg.log_start_at)[0]
s1.poll_sync(); open(p,"a").write(L("/seen-by-agent1")); print("agent1:",[e.http.path for e in s1.poll_sync()]); s1.close()
open(p,"a").write(L("/etc/passwd-while-agent-down")); open(p,"a").write(L("/.env-while-agent-down"))
s2=build_sources(cfg,ctx,cfg.log_start_at)[0]
print("agent2 first poll:",[e.http.path for e in s2.poll_sync()])
open(p,"a").write(L("/after-restart")); print("agent2 next poll:",[e.http.path for e in s2.poll_sync()])
