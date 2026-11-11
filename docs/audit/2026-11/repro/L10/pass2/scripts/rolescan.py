import json, urllib.request, secrets, re, time, sys
B="http://127.0.0.1:22000"; D=sys.argv[1]
for i in range(60):
    try: urllib.request.urlopen(B+"/api/v1/health",timeout=2); break
    except Exception: time.sleep(1)
adm=open(D+"/admin.jwt").read().strip()
def call(m,p,tok,body=None):
    req=urllib.request.Request(B+p,method=m,data=None if body is None else json.dumps(body).encode(),headers={"Content-Type":"application/json","Authorization":"Bearer "+tok})
    try: r=urllib.request.urlopen(req,timeout=10); return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()[:200]
pw=secrets.token_urlsafe(14); U="viewer"+secrets.token_hex(2)
print(call("POST","/api/v1/users",adm,{"username":U,"password":pw,"role":"viewer"})[0])
st,b=call("POST","/api/v1/auth/login",adm,{"username":U,"password":pw}); vt=json.loads(b)["access_token"]
spec=json.loads(urllib.request.urlopen(B+"/api/openapi.json").read())
for p,ops in spec["paths"].items():
    for m in ops:
        if m.upper() in ("POST","PUT","PATCH","DELETE") and "ingest" not in p and "/auth/" not in p:
            pp=re.sub(r"\{[^}]+\}","01a1c80f00000000000000000000dead",p)
            st,b=call(m.upper(),pp,vt,{})
            if st not in (401,403): print(m.upper(),p,st,b[:90])
