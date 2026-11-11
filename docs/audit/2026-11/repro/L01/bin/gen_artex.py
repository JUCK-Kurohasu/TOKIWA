"""Synthetic ARTEX-like gate.http events (behaviour inferred from /home/user/artex-jp source; see L01 findings)."""
import json, random, sys, uuid, datetime as dt
random.seed(7)
OUT = sys.argv[1]
T0 = dt.datetime(2026, 10, 1, 10, 0, tzinfo=dt.timezone.utc)
rows = []
def ev(ip, t, method, path, ua, hdr_order, status=200, ctype="text/html; charset=utf-8", size=2048, body=0, sess="", attack="recon", phase="recon", extra=None):
    h = {"host": "gate:8080"}
    for k in hdr_order:
        if k == "host": continue
        h[k] = {"user-agent": ua, "accept-encoding": "gzip", "accept": "*/*", "connection": "close"}.get(k, "x")
    if extra: h.update(extra)
    rows.append({"dataset": "gate.http", "destination": {"ip": "172.28.0.10", "port": 8080},
      "http": {"duration_ms": round(random.uniform(3, 40), 2), "header_order": list(h.keys()), "headers": h, "host": "gate",
               "http_version": "1.1", "method": method, "path": path, "request_body_size": body, "response_content_type": ctype,
               "response_size": size, "scheme": "http", "status": status, "user_agent": ua},
      "id": uuid.uuid4().hex, "kind": "http",
      "labels": {"actor": "ai_agent", "attack": attack, "phase": phase, "profile": "artex", "session": sess},
      "sensor_id": "sim", "source": {"ip": ip, "port": random.randint(30000, 60000)}, "tags": [],
      "timestamp": (T0 + dt.timedelta(seconds=t)).isoformat().replace("+00:00", "Z")})
think = lambda: random.uniform(4, 25)
CURL = "curl/7.88.1"; HC = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36"
BR_HDR = ["host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language"]
SQLI = ["/products?q=1'", "/products?q=1' OR '1'='1", "/products?q=1' OR 1=1--", "/products?q=1' UNION SELECT NULL--", "/products?q=1' UNION SELECT NULL,NULL--", "/products?q=1' UNION SELECT name,sql FROM sqlite_master--"]
# S1: full ARTEX run: enrich -> api-recon spider/harvest -> curl probing -> browser
ip, s, t = "198.51.100.101", "artex-full", 0.0
ev(ip, t, "GET", "/", "artex-enrich/1.0", ["host", "user-agent", "accept-encoding"], sess=s)
t += 40
for i, p in enumerate(["/", "/products", "/login", "/about", "/products?page=2", "/products/1", "/products/2", "/products/3", "/contact", "/search", "/cart", "/register"]):
    t += 0.1 + random.uniform(0.01, 0.05)
    ev(ip, t, "GET", p, "Mozilla/5.0 (spa-api-recon spider)", ["host", "user-agent", "accept-encoding", "connection"], sess=s)
t += think()
for burst in range(2):
    for j in range(20):
        ev(ip, t + random.uniform(0, 0.3), "GET", f"/static/js/chunk-{burst}-{j}.js", "Mozilla/5.0 (spa-api-recon)", ["host", "user-agent", "accept-encoding", "connection"], ctype="application/javascript", sess=s)
    t += 1.0
for p in ["/robots.txt", "/.env", "/api/internal/openapi.json", "/api/v1/users", "/api/v1/users/1", "/api/v1/users/2", "/admin"]:
    t += think(); ev(ip, t, "GET", p, CURL, ["host", "user-agent", "accept"], status=200 if "users" in p or "robots" in p else 404, ctype="application/json", sess=s)
for i, p in enumerate(SQLI):
    t += think(); ev(ip, t, "GET", p, CURL, ["host", "user-agent", "accept"], status=500 if i < 4 else 200, sess=s, attack="sqli", phase="exploit")
for p in ["/", "/login", "/products", "/products/1"]:
    t += think(); ev(ip, t, "GET", p, HC, BR_HDR, sess=s, phase="browse")
t += think(); ev(ip, t, "POST", "/login", HC, BR_HDR + ["content-type", "content-length", "origin", "referer"], status=302, body=40, sess=s, phase="browse")
# S2: browser-only (playwright-cli) ARTEX worker
ip, s, t = "198.51.100.102", "artex-browser", 3000.0
for p in ["/", "/login", "/products", "/products/1", "/products/2", "/cart", "/api/v1/orders/1001", "/api/v1/orders/1002", "/api/v1/orders/1000", "/account", "/products?q=test", "/products?q=%27"]:
    t += think(); ev(ip, t, "GET", p, HC, BR_HDR, status=500 if p.endswith("%27") else 200, sess=s, attack="idor" if "orders" in p else "recon")
# S3: curl-only re-issued through go-mitmproxy (Go net/http header set), LLM think gaps
ip, s, t = "198.51.100.103", "artex-curl-mitm", 6000.0
for p in ["/", "/robots.txt", "/login", "/api/v1/users", "/api/v1/users/1", "/api/v1/users/2", "/api/v1/users/3", "/.git/config", "/backup.sql"]:
    t += think(); ev(ip, t, "GET", p, CURL, ["host", "user-agent", "accept", "accept-encoding"], status=200 if "users" in p or p in ("/", "/login", "/robots.txt") else 404, sess=s)
for i, p in enumerate(SQLI):
    t += think(); ev(ip, t, "GET", p, CURL, ["host", "user-agent", "accept", "accept-encoding"], status=500 if i < 4 else 200, sess=s, attack="sqli", phase="exploit")
rows.sort(key=lambda r: r["timestamp"])
with open(OUT, "w") as f:
    for r in rows: f.write(json.dumps(r) + "\n")
print(len(rows))
