"""Item 2: API-style attack coverage (stateless single events + small stateful sequences)."""
import sys, json, datetime as dt
sys.path.insert(0, sys.argv[1])
from harness import *
from tokiwa.util import utcnow
J = "application/json"
single = {
 "nosql $ne login": ("/api/login", dict(method="POST", ct=J, body='{"username":"admin","password":{"$ne":null}}')),
 "nosql $where": ("/api/users", dict(method="POST", ct=J, body='{"$where":"sleep(5000)"}')),
 "nosql query [$regex]": ("/login?user=admin&pass[$regex]=.*", {}),
 "proto pollution json": ("/api/profile", dict(method="POST", ct=J, body='{"__proto__":{"isAdmin":true}}')),
 "proto pollution query": ("/api?__proto__[polluted]=1", {}),
 "constructor.prototype": ("/api?constructor[prototype][isAdmin]=1", {}),
 "mass assignment role": ("/api/users/me", dict(method="PATCH", ct=J, body='{"name":"x","role":"admin","isAdmin":true}')),
 "CRLF in query": ("/redirect?url=/%0d%0aSet-Cookie:%20sess=evil", {}),
 "open redirect //": ("/login?next=//evil.example/", {}),
 "open redirect https": ("/login?returnUrl=https://evil.example/", {}),
 "ssrf decimal ip": ("/fetch?url=http://2852039166/latest/meta-data/", {}),
 "ssrf hex ip": ("/fetch?url=http://0xa9fea9fe/latest/meta-data/", {}),
 "ssrf octal ip": ("/fetch?url=http://0251.0376.0251.0376/latest/", {}),
 "ssrf ipv6-mapped": ("/fetch?url=http://[::ffff:a9fe:a9fe]/latest/", {}),
 "ssrf aws ipv6": ("/fetch?url=http://[fd00:ec2::254]/latest/meta-data/", {}),
 "ssrf gcp name": ("/fetch?url=http://metadata.google.internal/computeMetadata/v1/", {}),
 "ssrf nip.io": ("/fetch?url=http://169.254.169.254.nip.io/latest/", {}),
 "ssrf localhost": ("/fetch?url=http://127.0.0.1:6379/", {}),
 "ssrf 0.0.0.0": ("/fetch?url=http://0.0.0.0:8080/admin", {}),
 "ssrf gopher": ("/fetch?url=gopher://127.0.0.1:6379/_INFO", {}),
 "ssrf file://": ("/fetch?url=file:///etc/passwd", {}),
 "jwt alg none (Authorization)": ("/api/me", dict(headers={"authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."})),
 "jwt kid traversal (Authorization)": ("/api/me", dict(headers={"authorization": "Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uL2Rldi9udWxsIn0.e30.x"})),
 "graphql introspection": ("/graphql", dict(method="POST", ct=J, body='{"query":"{__schema{types{name fields{name}}}}"}')),
 "graphql batch 50": ("/graphql", dict(method="POST", ct=J, body=json.dumps([{"query":"mutation{login(u:\"admin\",p:\"p%d\"){t}}" % i} for i in range(50)]))),
 "graphql alias brute": ("/graphql", dict(method="POST", ct=J, body=json.dumps({"query":"mutation{" + " ".join('a%d:login(u:"admin",p:"p%d"){t}' % (i, i) for i in range(50)) + "}"}))),
 "upload .php": ("/upload", dict(method="POST", ct="multipart/form-data; boundary=BB", body='--BB\r\nContent-Disposition: form-data; name="f"; filename="shell.php"\r\nContent-Type: image/png\r\n\r\n<?php system($_GET["c"]); ?>\r\n--BB--\r\n')),
 "upload .phtml/.jpg.php": ("/upload", dict(method="POST", ct="multipart/form-data; boundary=BB", body='--BB\r\nContent-Disposition: form-data; name="f"; filename="a.jpg.phtml"\r\n\r\nGIF89a\r\n--BB--\r\n')),
 "host header injection": ("/reset-password", dict(method="POST", headers={"x-forwarded-host": "evil.example"}, ct=J, body='{"email":"victim@example.com"}')),
}
rows = []
for n, (t, kw) in single.items():
    ids = run([direct_event(t, **kw)])[0]
    rows.append(f"| {n} | {', '.join(ids) or '-'} |")
# stateful sequences
base = utcnow()
def seq(name, evs):
    r = run_drafts(evs)
    ids = sorted({d.rule_id for ds in r for d in ds})
    rows.append(f"| {name} (n={len(evs)}) | {', '.join(ids) or '-'} |")
seq("IDOR enum /api/orders/1000..1060 all 200", [direct_event(f"/api/orders/{1000+i}", ts=base + dt.timedelta(seconds=i*2)) for i in range(60)])
seq("IDOR enum 403/200 mix", [direct_event(f"/api/users/{i}/profile", status=(200 if i%3 else 403), ts=base + dt.timedelta(seconds=i*2)) for i in range(60)])
seq("account enum 60 usernames 401", [direct_event("/api/login", method="POST", ct=J, body=json.dumps({"username":f"user{i}","password":"Winter2026!"}), status=401, ts=base + dt.timedelta(seconds=i*3)) for i in range(60)])
seq("password spray 30 x 401 slow (60s)", [direct_event("/api/login", method="POST", ct=J, body=json.dumps({"username":f"u{i}","password":"x"}), status=401, ts=base + dt.timedelta(seconds=i*60)) for i in range(30)])
seq("forgot-password enum 60 x 200/404", [direct_event("/api/forgot", method="POST", ct=J, body=json.dumps({"email":f"u{i}@corp.example"}), status=(200 if i%10==0 else 404), ts=base + dt.timedelta(seconds=i*2)) for i in range(60)])
out = "| case | rule ids fired (direct mode) |\n|---|---|\n" + "\n".join(rows)
open(f"{sys.argv[1]}/api_coverage.md", "w").write(out); print(out)
