from tokiwa.sensors.nginx import NginxJsonParser
from tokiwa.sensors.caddy import parse_caddy_record
from tokiwa.sensors.normalize import ParseContext, parse_ts
from tokiwa.sensors.logtail import LogSource
p=NginxJsonParser(ParseContext(sensor_id="t"))
# nginx escape=default renders a client '"' as \x22 (not valid JSON)
line_default = '{"time_local":"11/Nov/2026:09:00:00 +0900","remote_addr":"203.0.113.9","request":"GET /?id=1%27+OR+1=1-- HTTP/1.1","status":"200","http_user_agent":"sqlmap\\x22probe"}'
print("escape=default line ->", p.parse(line_default))
for v in ["2026-11-11 09:00:00","2026-11-11T09:00:00","11/Nov/2026:09:00:00 +0900","2026/11/11 09:00:00","Nov 11 09:00:00","1731283200123456"]:
    print(repr(v),"->",parse_ts(v))
from datetime import datetime
ev=parse_caddy_record({"ts":"2026/11/11 09:00:00.000","request":{"method":"GET","uri":"/x","remote_ip":"1.2.3.4"}},ParseContext())
print("caddy wall ts ->",ev.timestamp, "(now fallback)")
