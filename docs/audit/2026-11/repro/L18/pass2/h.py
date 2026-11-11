"""helpers: python h.py <cmd> ... ; uses env for data dir"""
import json, os, sys, subprocess, time, secrets, datetime, urllib.request
M=os.path.dirname(os.path.abspath(__file__)); B="/home/user/TOKIWA/backend"; PY=B+"/.venv/bin/python"
def req(port, method, path, body=None, headers=None, timeout=30):
    h={"content-type":"application/json"}; h.update(headers or {})
    r=urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp: return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()
    except Exception as e: return -1, repr(e)
def start(d, port, pypath=None, extra_env=None):
    env=dict(os.environ); env.update({"TOKIWA_SERVER__DATA_DIR":d,"TOKIWA_DATABASE__URL":f"sqlite+aiosqlite:///{d}/tokiwa.db","TOKIWA_LLM__PROVIDER":"mock"})
    if pypath: env["PYTHONPATH"]=pypath
    env.update(extra_env or {})
    os.makedirs(d, exist_ok=True)
    p=subprocess.Popen([PY,"-m","tokiwa.cli","serve","--port",str(port)] if False else [B+"/.venv/bin/tokiwa","serve","--port",str(port)] if not pypath else [PY,"-c","import sys;from tokiwa.cli import app;sys.argv=['tokiwa','serve','--port','%d'];app()"%port],
        cwd=d, env=env, stdout=open(d+"/server.log","a"), stderr=subprocess.STDOUT)
    open(d+"/server.pid","w").write(str(p.pid))
    for _ in range(60):
        if req(port,"GET","/api/v1/auth/status")[0]==200: return p.pid
        time.sleep(0.5)
    return p.pid
def stop(d, sig=15):
    pid=int(open(d+"/server.pid").read()); os.kill(pid, sig)
    for _ in range(40):
        try: os.kill(pid,0); time.sleep(0.25)
        except OSError: return
def setup(port, d):
    pw=secrets.token_urlsafe(12); open(d+"/admin.pw","w").write(pw); os.chmod(d+"/admin.pw",0o600)
    s,b=req(port,"POST","/api/v1/auth/setup",{"username":"admin","password":pw}); return s, (json.loads(b).get("access_token") if s==200 else b)
def login(port,d,user="admin"):
    s,b=req(port,"POST","/api/v1/auth/login",{"username":user,"password":open(d+f"/{user}.pw").read()}); return s,(json.loads(b).get("access_token") if s==200 else b)
def token(port, jwt, d, name="gate-1", scopes=("ingest","gate")):
    s,b=req(port,"POST","/api/v1/tokens",{"name":name,"scopes":list(scopes)},{"authorization":"Bearer "+jwt})
    if s in (200,201):
        t=json.loads(b).get("token"); open(d+"/ingest.tok","w").write(t); os.chmod(d+"/ingest.tok",0o600); return s
    return s,b
def ev(i, ip="203.0.113.10", path="/"):
    return {"timestamp":datetime.datetime.now(datetime.timezone.utc).isoformat(),"kind":"http","dataset":"gate.http",
            "source":{"ip":ip,"port":50000},"destination":{"ip":"10.0.0.5","port":8080},
            "http":{"method":"GET","scheme":"http","host":"app.lab","path":path,"query":f"id={i}' OR 1=1--","user_agent":"python-requests/2.31","status":200,"headers":{}}}
def ingest(port, d, n=50, start=0):
    t=open(d+"/ingest.tok").read(); return req(port,"POST","/api/v1/ingest/events",{"events":[ev(start+i) for i in range(n)]},{"x-tokiwa-token":t})
