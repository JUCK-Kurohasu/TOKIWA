import sys, json, datetime as dt
sys.path.insert(0, sys.argv[1])
from harness import *
from tokiwa.detect.sigma.parser import parse_rule
from tokiwa.util import utcnow
def R(det, cat="webserver"):
    return parse_rule(f"title: t\nlogsource: {{category: {cat}}}\ndetection:\n{det}\nlevel: low\n")
print("== sigma semantics")
cases = [
 ("escaped star literal", "  sel:\n    cs-uri-query|contains: 'a\\*b'\n  condition: sel", "/x?q=aXXb", False),
 ("escaped star literal (lit)", "  sel:\n    cs-uri-query|contains: 'a\\*b'\n  condition: sel", "/x?q=a*b", True),
 ("? single char", "  sel:\n    cs-uri-query: 'q=a?c'\n  condition: sel", "/x?q=abc", True),
 ("contains|all", "  sel:\n    cs-uri-query|contains|all: ['union','select']\n  condition: sel", "/x?q=union", False),
 ("not missing field", "  sel:\n    cs-referer: 'x'\n  condition: not sel", "/x", True),
 ("null value = missing", "  sel:\n    cs-referer: null\n  condition: sel", "/x", True),
 ("1 of sel*", "  sel1:\n    cs-uri-query|contains: 'zzz'\n  sel2:\n    cs-uri-query|contains: 'q='\n  condition: 1 of sel*", "/x?q=1", True),
 ("re case-sensitive", "  sel:\n    cs-uri-query|re: 'UNION'\n  condition: sel", "/x?q=union", False),
 ("uri-query vs encoded", "  sel:\n    cs-uri-query|contains: 'union select'\n  condition: sel", "/x?q=union%20select", True),
 ("uri-query double enc", "  sel:\n    cs-uri-query|contains: 'union select'\n  condition: sel", "/x?q=union%2520select", True),
 ("plus as space", "  sel:\n    cs-uri-query|contains: 'union select'\n  condition: sel", "/x?q=union+select", True),
 ("numeric gt on status", "  sel:\n    sc-status|gte: 500\n  condition: sel", "/x", False),
 ("keyword search body", "  keywords:\n    - 'evilmarker'\n  condition: keywords", "/x", True),
]
for name, det, tgt, exp in cases:
    try:
        r = R(det); kw = dict(method="POST", ct="text/plain", body="evilmarker") if "keyword" in name else {}
        got = r.matches(direct_event(tgt, **kw))
        print(f"{'OK ' if got == exp else 'BAD'} {name}: got={got} exp={exp}")
    except Exception as e:
        print("ERR", name, type(e).__name__, str(e)[:120])
print("== rate / stateful")
base = utcnow()
def seq(name, evs):
    r = run_drafts(evs); ids = sorted({d.rule_id for ds in r for d in ds if d.rule_id.startswith(("web.", "ai."))}); print(f"{name} (n={len(evs)}): {ids or '-'}")
J = "application/json"
seq("cred: 40 fails, 1 per 31s", [direct_event("/api/login", method="POST", ct=J, body=json.dumps({"username": f"u{i}", "password": "x"}), status=401, ts=base + dt.timedelta(seconds=31 * i)) for i in range(40)])
seq("cred: 60 fails status 200 {error}", [direct_event("/api/login", method="POST", ct=J, body=json.dumps({"username": f"u{i}", "password": "x"}), status=200, ts=base + dt.timedelta(seconds=2 * i)) for i in range(60)])
seq("cred: 60 fails status 422", [direct_event("/api/login", method="POST", ct=J, body=json.dumps({"username": f"u{i}", "password": "x"}), status=422, ts=base + dt.timedelta(seconds=2 * i)) for i in range(60)])
seq("cred: 60 fails GraphQL login mutation 200", [direct_event("/graphql", method="POST", ct=J, body=json.dumps({"query": 'mutation{login(u:"u%d",p:"x"){t}}' % i}), status=200, ts=base + dt.timedelta(seconds=2 * i)) for i in range(60)])
seq("cred: 60 fails over 30 IPs (2 each, fast)", [direct_event("/api/login", method="POST", ct=J, body=json.dumps({"username": f"u{i}", "password": "x"}), status=401, ip=f"198.51.100.{i % 30 + 1}", ts=base + dt.timedelta(seconds=2 * i)) for i in range(60)])
seq("dirbust: 100 x 404, 1 per 2.1s", [direct_event(f"/p{i}", status=404, ts=base + dt.timedelta(seconds=2.1 * i)) for i in range(100)])
seq("dirbust: 100 x 404 fast over 10 IPs", [direct_event(f"/p{i}", status=404, ip=f"198.51.100.{i % 10 + 1}", ts=base + dt.timedelta(seconds=0.3 * i)) for i in range(100)])
seq("dirbust: 100 x 404 fast, 1 IP (control)", [direct_event(f"/p{i}", status=404, ts=base + dt.timedelta(seconds=0.3 * i)) for i in range(100)])
seq("dirbust: 100 fast, app returns 200 soft-404", [direct_event(f"/p{i}", status=200, ts=base + dt.timedelta(seconds=0.3 * i)) for i in range(100)])
seq("flood: 19 rps 30s", [direct_event("/", ts=base + dt.timedelta(seconds=i / 19)) for i in range(570)])
print("== benign FP sample")
benign = {
 "search 'select from union station'": "/search?q=" + "select%20a%20seat%20from%20union%20station",
 "search drop table": "/search?q=how%20to%20drop%20table%20in%20postgres",
 "O'Reilly name": "/users?name=O%27Reilly%20or%20Smith",
 "math 1=1": "/calc?expr=1%3D1%20and%202%3E1",
 "path ../ docs": "/docs?file=guide/../intro.md",
 "url param": "/share?url=https%3A%2F%2Fexample.com%2Fpage",
 "localhost dev url": "/settings?callback=http%3A%2F%2Flocalhost%3A3000%2Fcb",
 "template text {{name}}": "/mail?tpl=Hello%20%7B%7Bname%7D%7D",
 "shell-ish text": "/kb?q=use%20%60ls%20-la%60%20%7C%20grep%20foo",
 "html snippet": "/forum?msg=%3Cb%3Ebold%3C%2Fb%3E%20and%20%3Ci%3Eit%3C%2Fi%3E",
}
for n, t in benign.items():
    print(f"{n}: {run([direct_event(t)])[0] or '-'}")
bodies = {
 "json code snippet": {"code": "for (i=0;i<n;i++) { if (a[i] == \"x\") return; } // select * from t where id='1'"},
 "json markdown w/ script tag": {"md": "Use `<script src=app.js></script>` in index.html"},
 "json py snippet": {"code": "import os\nos.system('ls')\nprint(open('/etc/hosts').read())"},
 "json bash help": {"q": "how do I run $(whoami) in bash; cat /etc/passwd shows users"},
}
for n, b in bodies.items():
    print(f"{n}: {run([direct_event('/api/chat2', method='POST', ct=J, body=json.dumps(b))])[0] or '-'}")
