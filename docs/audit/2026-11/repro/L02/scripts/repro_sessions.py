"""L02 repro: how TOKIWA's sessionizer/scoring reacts to observable behaviours of real AI attack tooling.
Pure in-process (no network, no LLM). Run with the TOKIWA venv python."""
from __future__ import annotations
import random, json, sys
from datetime import datetime, timedelta, timezone
from tokiwa.schemas.events import Event, EventKind, HttpInfo, Endpoint
from tokiwa.aidetect.sessions import SessionTracker
from tokiwa.aidetect.fingerprints import fingerprint_info

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc)
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36"
FF = "Mozilla/5.0 (X11; Linux x86_64; rv:{v}.0) Gecko/20100101 Firefox/{v}.0"

def ev(ts, ip, ua, path, query=None, status=200, headers=None, scheme="http"):
    h = {"user-agent": ua, "accept": "*/*", "accept-language": "en", "accept-encoding": "gzip"}
    if headers is not None:
        h = headers | {"user-agent": ua}
    return Event(kind=EventKind.HTTP, dataset="gate.http", timestamp=ts, source=Endpoint(ip=ip),
                 http=HttpInfo(method="GET", scheme=scheme, host="victim.local", path=path, query=query,
                               headers=h, header_order=list(h), user_agent=ua, status=status))

def agent_trace(rng, *, ua_fn, ip_fn, think=(2.0, 12.0)):
    """LLM-agent-like trace: spec fetch, discovered routes, then error-conditioned SQLi variants with think gaps."""
    t = T0; out = []
    def add(path, q=None, st=200, gap=0.1):
        nonlocal t
        t = t + timedelta(seconds=gap)
        out.append(ev(t, ip_fn(), ua_fn(), path, q, st))
    add("/openapi.json", gap=0)
    for i, r in enumerate(["/api/v1/users", "/api/v1/orders", "/api/v1/products", "/api/v1/admin/stats", "/api/v1/search"]):
        add(r, gap=rng.uniform(0.05, 0.25) if i else rng.uniform(*think))
    payloads = ["q=laptop'", "q=laptop' OR '1'='1", "q=laptop' OR '1'='1' --", "q=laptop'/**/OR/**/1=1--",
                "q=laptop' UNION SELECT NULL--", "q=laptop' UNION SELECT NULL,NULL--", "q=laptop%27%20UNION%20SELECT%20username,password%20FROM%20users--"]
    for p in payloads:
        add("/api/v1/search", p, st=500, gap=rng.uniform(*think))
        add("/api/v1/products", "id=1", gap=rng.uniform(0.05, 0.2))
    return out

def run(name, events):
    tr = SessionTracker()
    tr.observe_batch(events)
    ss = tr.sessions()
    best = max(ss, key=lambda s: s.ai_score)
    cls = {}
    for s in ss:
        cls[str(s.classification)] = cls.get(str(s.classification), 0) + 1
    print(json.dumps({"scenario": name, "events": len(events), "sessions": len(ss), "classifications": cls,
                      "max_ai_score": best.ai_score, "max_session_requests": max(s.request_count for s in ss),
                      "top_indicators": [i["key"] for i in best.indicators[:5]]}, ensure_ascii=False))

rng = random.Random(7)
fixed_ua = CHROME.format(v=131)
run("baseline: fixed IP + fixed python-httpx UA", agent_trace(rng, ua_fn=lambda: "python-httpx/0.28.1", ip_fn=lambda: "203.0.113.10"))
rng = random.Random(7)
run("baseline: fixed IP + fixed Chrome UA (nuclei-like header set)", agent_trace(rng, ua_fn=lambda: fixed_ua, ip_fn=lambda: "203.0.113.10"))
rng = random.Random(7); r2 = random.Random(1)
uas = [CHROME.format(v=v) for v in range(110, 140)] + [FF.format(v=v) for v in range(115, 140)]
run("per-request UA rotation (nuclei useragent.PickRandom per request)", agent_trace(rng, ua_fn=lambda: r2.choice(uas), ip_fn=lambda: "203.0.113.10"))
rng = random.Random(7); r3 = random.Random(2)
run("per-request IP rotation (residential proxy pool) + fixed httpx UA", agent_trace(rng, ua_fn=lambda: "python-httpx/0.28.1", ip_fn=lambda: f"198.51.100.{r3.randint(1,254)}"))
rng = random.Random(7)
run("AI agent driving sqlmap (default sqlmap UA)", agent_trace(rng, ua_fn=lambda: "sqlmap/1.8.11#stable (https://sqlmap.org)", ip_fn=lambda: "203.0.113.10"))
rng = random.Random(7)
run("jittered pacing: think gaps 0.3-0.95s (mid band, e.g. fast model / Strix-style parallel agents)", agent_trace(rng, ua_fn=lambda: "python-httpx/0.28.1", ip_fn=lambda: "203.0.113.10", think=(0.3, 0.95)))
rng = random.Random(7)
run("jittered pacing: think gaps 65-180s (slow/human-like delays)", agent_trace(rng, ua_fn=lambda: "python-httpx/0.28.1", ip_fn=lambda: "203.0.113.10", think=(65, 180)))

print("--- fingerprint checks")
nuclei_like = {"user-agent": fixed_ua, "accept": "*/*", "accept-language": "en", "accept-encoding": "gzip"}
for scheme in ("http", "https"):
    fi = fingerprint_info(fixed_ua, nuclei_like, scheme=scheme)
    print(json.dumps({"case": f"Chrome UA + nuclei header set, scheme={scheme}", "family": str(fi.family), "anomalies": fi.anomalies}))
for ua in ["Ares-Agent", "PentAGI", "Mozilla/5.0 (compatible; Strix/1.0)", "Go-http-client/2.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/131.0.0.0 Safari/537.36",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0", "Fuzz Faster U Fool v2.1.0-dev",
           "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
           "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 (compatible; Operator)"]:
    h = {"user-agent": ua, "accept": "*/*", "connection": "close"}
    fi = fingerprint_info(ua, h, scheme="http")
    print(json.dumps({"ua": ua[:70], "family": str(fi.family), "tool": fi.tool, "automation": fi.is_automation, "anomalies": fi.anomalies}))
