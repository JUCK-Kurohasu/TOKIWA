"""Send canary/honeytoken usage variants through the Gate; map trips by User-Agent. Prints no token values."""
import base64, http.client, json, re, sys, time, urllib.request
GATE=("127.0.0.1", int(sys.argv[1])); API=sys.argv[2]; JWT=open(sys.argv[3]).read().strip(); tag=sys.argv[4]
html=urllib.request.urlopen(f"http://{GATE[0]}:{GATE[1]}/").read().decode()
T=re.search(r"dbg_[A-Za-z0-9]{24}", html).group(0)
env=urllib.request.urlopen(f"http://{GATE[0]}:{GATE[1]}/.env").read().decode()
API_KEY=re.search(r"INTERNAL_API_KEY=(\S+)", env).group(1)
DBU=re.search(r"postgresql://([^:]+):([^@]+)@", env); DB_USER, DB_PW = DBU.group(1), DBU.group(2)
AWS=re.search(r"AWS_ACCESS_KEY_ID=(\S+)", env).group(1)
esc=T.replace("_","\\_")
V=[ # (name, method, path, headers, body)
 ("hdr_exact","GET","/",{"X-Debug-Auth":T},None),
 ("path_exact","GET",f"/api/internal/{T}/",{},None),
 ("hdr_lowername","GET","/",{"x-debug-auth":T},None),
 ("hdr_bearer_prefix","GET","/",{"X-Debug-Auth":"Bearer "+T},None),
 ("authz_bearer","GET","/api/products",{"Authorization":"Bearer "+T},None),
 ("x_api_key","GET","/api/products",{"X-API-Key":T},None),
 ("cookie","GET","/",{"Cookie":"debug_auth="+T},None),
 ("q_debugToken","GET",f"/api/internal/?debugToken={T}",{},None),
 ("q_debug_auth","GET",f"/?debug_auth={T}",{},None),
 ("q_X-Debug-Auth","GET",f"/?X-Debug-Auth={T}",{},None),
 ("q_auth","GET",f"/?auth={T}",{},None),
 ("q_ref","GET",f"/?ref={T}",{},None),
 ("json_X-Debug-Auth","POST","/api/chat",{"Content-Type":"application/json"},json.dumps({"X-Debug-Auth":T})),
 ("json_debug","POST","/api/chat",{"Content-Type":"application/json"},json.dumps({"message":"debug "+T})),
 ("md_escaped_path","GET",f"/api/internal/{esc}/",{},None),
 ("md_escaped_hdr","GET","/",{"X-Debug-Auth":esc},None),
 ("lowercase_hdr","GET","/",{"X-Debug-Auth":T.lower()},None),
 ("urlenc_path","GET","/api/internal/%64"+T[1:]+"/",{},None),
 ("dblenc_path","GET","/api/internal/%2564"+T[1:]+"/",{},None),
 ("split_hdr","GET","/",{"X-Debug-Auth":T[:12],"X-Debug-Auth-2":T[12:]},None),
 ("b64_hdr","GET","/",{"X-Debug-Auth":base64.b64encode(T.encode()).decode()},None),
 ("hdr_after_64","GET","/",{**{f"X-Pad-{i}":"x" for i in range(64)},"X-Debug-Auth":T},None),
 ("upper_prefix_path","GET",f"/API/INTERNAL/{T}/",{},None),
 ("api_key_bearer","GET","/api/orders",{"Authorization":"Bearer "+API_KEY},None),
 ("api_key_xapikey","GET","/api/orders",{"X-API-Key":API_KEY},None),
 ("api_key_q_api_key","GET",f"/api/orders?api_key={API_KEY}",{},None),
 ("api_key_custom_hdr","GET","/api/orders",{"X-Internal-Api-Key":API_KEY},None),
 ("db_login_json","POST","/api/login",{"Content-Type":"application/json"},json.dumps({"username":DB_USER,"password":DB_PW})),
 ("db_basic","GET","/api/orders",{"Authorization":"Basic "+base64.b64encode(f"{DB_USER}:{DB_PW}".encode()).decode()},None),
 ("db_pw_only_json","POST","/api/login",{"Content-Type":"application/json"},json.dumps({"username":"admin","password":DB_PW})),
 ("aws_sigv4_hdr","GET","/",{"Authorization":f"AWS4-HMAC-SHA256 Credential={AWS}/20261109/ap-northeast-1/s3/aws4_request, SignedHeaders=host, Signature=abc"},None),
 ("aws_q_credential","GET",f"/?X-Amz-Credential={AWS}%2F20261109%2Fap-northeast-1%2Fs3%2Faws4_request",{},None),
]
res={}
for name,m,p,h,b in V:
    c=http.client.HTTPConnection(*GATE, timeout=10)
    hh={"User-Agent":f"{tag}-{name}",**h}
    c.putrequest(m,p,skip_accept_encoding=True)
    for k,v in hh.items(): c.putheader(k,v)
    data=b.encode() if b else None
    if data: c.putheader("Content-Length",str(len(data)))
    c.endheaders(data); r=c.getresponse(); r.read(); res[name]={"status":r.status}; c.close()
time.sleep(6)
req=urllib.request.Request(API+"/api/v1/deception/trips?limit=200",headers={"Authorization":"Bearer "+JWT})
trips=json.load(urllib.request.urlopen(req))["items"]
for e in trips:
    ua=(e.get("http") or {}).get("user_agent") or ""
    if ua.startswith(tag+"-"):
        n=ua[len(tag)+1:]; res.setdefault(n,{}).setdefault("trips",[]).append(e["deception"]["detail"])
for name,_,_,_,_ in V:
    print(f"{name:20s} status={res[name]['status']} trips={sorted(res[name].get('trips',[]))}")
