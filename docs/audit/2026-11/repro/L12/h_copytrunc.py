"""Rename-rotation while the tailer lags: how many lines survive?"""
import json, os, sys, tempfile
from tokiwa.sensors.logtail import FileTailer, LogSource
from tokiwa.sensors.nginx import NginxJsonParser
from tokiwa.sensors.normalize import ParseContext
d = sys.argv[1]; p = os.path.join(d, "access.log")
for f in os.listdir(d): os.remove(os.path.join(d, f))
open(p, "w").close()
src = LogSource(FileTailer(p, start_at="end"), NginxJsonParser(ParseContext(sensor_id="t")))
src.poll_sync()  # first poll: seek to end
pad = "A" * 900
with open(p, "a") as fh:  # ~10 MiB of junk requests written between two polls (attacker flood)
    for i in range(11000):
        fh.write(json.dumps({"request_method": "GET", "request_uri": f"/junk/{i}?{pad}", "remote_addr": "198.51.100.9", "status": "404"}) + "\n")
    fh.write(json.dumps({"request_method": "GET", "request_uri": "/etc/passwd?ATTACK=1", "remote_addr": "203.0.113.66", "status": "200"}) + "\n")
import shutil; shutil.copy(p, p + ".1"); open(p, "r+").truncate(0)  # logrotate 'create' (rename) + nginx reopen
evs = src.poll_sync() + src.poll_sync() + src.poll_sync()
print("written_lines=11001 bytes=%d" % os.path.getsize(p + ".1"))
print("events=%d parse_errors=%d attack_seen=%s" % (len(evs), src.errors, any(e.http and "ATTACK" in (e.http.query or "") for e in evs)))
