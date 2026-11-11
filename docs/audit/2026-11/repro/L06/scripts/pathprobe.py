"""Send raw request-targets to a gate; print status + whether the raw upstream received it (decoy vs proxied)."""
import socket, sys, json, os, time
PORT=int(sys.argv[1]); LOG=sys.argv[2]
def send(target, extra=b""):
    s=socket.create_connection(("127.0.0.1",PORT)); s.settimeout(3)
    s.sendall(b"GET "+target+b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"+extra+b"\r\n")
    d=b""
    try:
        while True:
            c=s.recv(65536)
            if not c: break
            d+=c
    except Exception: pass
    s.close(); return d.split(b"\r\n",1)[0].decode("latin-1","replace")
targets=[l.encode("latin-1") for l in sys.argv[3:]]
for t in targets:
    n0=sum(1 for _ in open(LOG)) if os.path.exists(LOG) else 0
    st=send(t); time.sleep(0.15)
    lines=open(LOG).read().splitlines()[n0:] if os.path.exists(LOG) else []
    up=[json.loads(l).get("reqline", json.loads(l).get("head","")[:80]) for l in lines]
    print(f"{t.decode('latin-1'):40} -> {st:28} upstream={'YES '+str(up)[:70] if up else 'no (decoy/local)'}")
