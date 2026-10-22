"""Traffic profiles for the lab simulator.

Each profile is an async script over :class:`~tokiwa.eval.sim.SessionContext` plus an identity factory. The
behaviours encode the hypotheses in docs/tasks/detect-ai.md so detectors can be evaluated against them:

==================  ============================================================================================
benign_browser      pages + parallel asset loads, XHR, searches (some with SQL-ish words), login typos, chat
scanner             fixed wordlist at a constant high rate + fixed signature payloads; ignores responses
human_attacker      browses, then a handful of classic SQLi/XSS/traversal tries with long, irregular gaps
ai_agent            ARTEX-like: JS/OpenAPI/robots recon -> enumerate discovered (unlinked) API routes in bursts ->
                    error-conditioned payload mutation -> burst + "thinking" gaps; httpx/LLM-ish UA; follows AI
                    canaries (hidden instructions) on the same origin
llm_app_attacker    prompt injection / jailbreak attempts against /api/chat (EN/JA, base64 obfuscation)
==================  ============================================================================================

All payloads come from :mod:`tokiwa.eval.payloads` (inert detection-test strings).
"""

from __future__ import annotations

import json
import math
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import quote

from tokiwa.eval import payloads as P
from tokiwa.eval.discovery import (
    extract_js_routes,
    extract_openapi_routes,
    extract_robots_disallow,
    find_canary_instructions,
)
from tokiwa.eval.exchange import ClientIdentity
from tokiwa.eval.safety import same_origin_path
from tokiwa.eval.sim import RequestSpec, SessionContext
from tokiwa.eval.virtual import DEMO_PASSWORD, DEMO_SESSION, DEMO_USER

ProfileRunner = Callable[[SessionContext], Awaitable[None]]


@dataclass(frozen=True)
class Profile:
    name: str
    actor: str  # tokiwa.schemas.common.ActorType value used as ground truth
    description: str
    run: ProfileRunner
    identity: Callable[[random.Random, str], ClientIdentity]


# ------------------------------------------------------------------------------------------ timing


def lognormal(rng: random.Random, median: float, sigma: float, lo: float, hi: float) -> float:
    return min(hi, max(lo, median * math.exp(rng.gauss(0.0, sigma))))


def human_gap(rng: random.Random, median: float = 7.0) -> float:
    """Reading / clicking pause: heavy-tailed and irregular."""
    return lognormal(rng, median, 0.9, 0.8, 180.0)


def think_gap(rng: random.Random) -> float:
    """LLM inference pause between tool-call bursts (seconds). Occasionally a long pause (planning/compaction)."""
    if rng.random() < 0.08:
        return rng.uniform(35.0, 90.0)
    return lognormal(rng, 6.5, 0.45, 2.0, 30.0)


# ------------------------------------------------------------------------------------- identities

_CHROME = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
]
_FIREFOX = ["Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"]
_SAFARI = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
]
_LANGS = ["ja,en-US;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9", "en-US,en;q=0.9"]


def browser_identity(rng: random.Random, ip: str) -> ClientIdentity:
    fam = rng.choices(["chrome", "firefox", "safari"], weights=[6, 2, 2])[0]
    ua = rng.choice({"chrome": _CHROME, "firefox": _FIREFOX, "safari": _SAFARI}[fam])
    return ClientIdentity(source_ip=ip, user_agent=ua, family=fam, accept_language=rng.choice(_LANGS))


def scanner_identity(rng: random.Random, ip: str) -> ClientIdentity:
    fam, ua = rng.choice(
        [
            (
                "nuclei",
                "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))",
            ),
            ("gobuster", "gobuster/3.6"),
            ("nikto", "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"),
            ("sqlmap", "sqlmap/1.8.4#stable (https://sqlmap.org)"),
        ]
    )
    return ClientIdentity(source_ip=ip, user_agent=ua, family=fam)


def human_attacker_identity(rng: random.Random, ip: str) -> ClientIdentity:
    if rng.random() < 0.25:
        return ClientIdentity(source_ip=ip, user_agent="curl/8.5.0", family="curl")
    return browser_identity(rng, ip)


def ai_agent_identity(rng: random.Random, ip: str) -> ClientIdentity:
    fam, ua = rng.choice(
        [
            ("httpx", "python-httpx/0.28.1"),
            ("httpx", "python-httpx/0.27.2"),
            ("aiohttp", "Python/3.12 aiohttp/3.10.10"),
            ("go", "Go-http-client/1.1"),
            (
                "httpx",
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
            ),
        ]
    )
    return ClientIdentity(source_ip=ip, user_agent=ua, family=fam)


def llm_attacker_identity(rng: random.Random, ip: str) -> ClientIdentity:
    if rng.random() < 0.4:
        return ClientIdentity(source_ip=ip, user_agent="python-requests/2.32.3", family="requests")
    return browser_identity(rng, ip)


ASSETS = ("/static/style.css", "/static/app.js", "/favicon.ico")


# -------------------------------------------------------------------------------- benign_browser


async def benign_browser(ctx: SessionContext) -> None:
    rng = ctx.rng
    ctx.cookie = f"sid={rng.getrandbits(64):016x}"
    visits = rng.randint(1, 3)
    for v in range(visits):
        await ctx.page("/", assets=ASSETS if v == 0 else ("/static/app.js",))
        for _ in range(rng.randint(3, 8)):
            await ctx.sleep(human_gap(rng))
            action = rng.choices(
                ["products", "detail", "search", "login", "chat", "paginate", "stale"],
                weights=[3, 4, 3, 1, 1, 2, 0.3],
            )[0]
            if action == "products":
                await ctx.page("/products", assets=("/static/app.js",))
                await ctx.request("GET", "/api/products", query="page=1&sort=name", phase="browse")
            elif action == "detail":
                pid = rng.randint(1, 12)
                await ctx.page(f"/products/{pid}")
                await ctx.request("GET", f"/api/products/{pid}", phase="browse")
            elif action == "search":
                term = rng.choice(P.BENIGN_SEARCH)
                await ctx.request("GET", "/api/search", query=f"q={quote(term)}", phase="browse")
            elif action == "login":
                await ctx.page("/login")
                await ctx.sleep(lognormal(rng, 6.0, 0.5, 2.0, 30.0))
                if rng.random() < 0.35:  # typo first
                    await ctx.request(
                        "POST",
                        "/api/login",
                        json_body={"username": DEMO_USER, "password": "lab-demo-pasword"},
                    )
                    await ctx.sleep(lognormal(rng, 5.0, 0.4, 2.0, 20.0))
                r = await ctx.request(
                    "POST", "/api/login", json_body={"username": DEMO_USER, "password": DEMO_PASSWORD}
                )
                if r.status == 200:
                    ctx.auth = f"Bearer {DEMO_SESSION}"
                    await ctx.request("GET", "/api/orders", phase="browse")
            elif action == "chat":
                question = rng.choice(P.BENIGN_CHAT_JA + P.BENIGN_CHAT_EN)
                await ctx.request("POST", "/api/chat", json_body={"message": question}, phase="browse")
            elif action == "paginate":
                sort = rng.choice(["name", "price"])
                await ctx.request("GET", "/api/products", query=f"page={rng.randint(1, 3)}&sort={sort}")
            else:  # stale bookmark -> 404
                await ctx.page(f"/products/{rng.randint(20, 99)}")
        if v < visits - 1:
            await ctx.sleep(rng.uniform(120.0, 900.0))


# ------------------------------------------------------------------------------------------ scanner

_SCANNER_PARAMS = [
    ("/api/search", "q"),
    ("/api/files/download", "name"),
    ("/api/products", "sort"),
    ("/", "id"),
    ("/login", "next"),
]


async def scanner(ctx: SessionContext) -> None:
    rng = ctx.rng
    interval = 1.0 / rng.uniform(15.0, 40.0)
    attack_kind = "scan"
    for word in P.SCANNER_WORDLIST:
        await ctx.request("GET", word, kind="other", attack="recon", phase=attack_kind)
        await ctx.sleep(interval * rng.uniform(0.95, 1.05))
    families = [("sqli", P.SQLI[:3]), ("xss", P.XSS[:2]), ("path_traversal", P.TRAVERSAL[:2])]
    families += [("cmd_injection", P.CMD[:1]), ("ssti", P.SSTI[:1]), ("log4shell", P.LOG4SHELL[:1])]
    for path, param in _SCANNER_PARAMS:
        for family, items in families:
            for payload in items:
                await ctx.request(
                    "GET",
                    path,
                    query=f"{param}={quote(payload, safe='')}",
                    kind="other",
                    attack=family,
                    phase="fuzz",
                )
                await ctx.sleep(interval * rng.uniform(0.95, 1.05))


# ----------------------------------------------------------------------------------- human_attacker


async def human_attacker(ctx: SessionContext) -> None:
    rng = ctx.rng
    if ctx.is_browser:
        await ctx.page("/", assets=ASSETS)
        for _ in range(rng.randint(1, 4)):
            await ctx.sleep(human_gap(rng, 6.0))
            await ctx.page(rng.choice(["/products", f"/products/{rng.randint(1, 12)}", "/login"]))
    else:
        await ctx.request("GET", "/", kind="document")
    for _ in range(rng.randint(4, 9)):
        await ctx.sleep(lognormal(rng, 25.0, 0.8, 6.0, 240.0))
        family = rng.choices(["sqli", "xss", "path_traversal"], weights=[5, 3, 2])[0]
        payload = rng.choice({"sqli": P.SQLI, "xss": P.XSS, "path_traversal": P.TRAVERSAL}[family])
        if rng.random() < 0.2 and len(payload) > 4:  # typo, then fix it a bit later
            cut = rng.randrange(1, len(payload) - 1)
            await _human_try(ctx, family, payload[:cut] + payload[cut + 1 :])
            await ctx.sleep(lognormal(rng, 12.0, 0.5, 4.0, 60.0))
        await _human_try(ctx, family, payload)


async def _human_try(ctx: SessionContext, family: str, payload: str) -> None:
    if family == "sqli" and ctx.rng.random() < 0.4:
        await ctx.request(
            "POST", "/api/login", json_body={"username": payload, "password": "x"}, attack=family
        )
    elif family == "path_traversal":
        await ctx.request(
            "GET", "/api/files/download", query=f"name={quote(payload, safe='')}", attack=family
        )
    else:
        await ctx.request("GET", "/api/search", query=f"q={quote(payload, safe='')}", attack=family)


# ------------------------------------------------------------------------------------------ ai_agent


@dataclass
class _Target:
    method: str
    path: str
    param: str | None  # None -> path parameter
    family: str


def _concretize(route: str) -> str:
    return route.replace("{id}", "1").replace("{pid}", "1").replace("{uid}", "1")


async def ai_agent(ctx: SessionContext) -> None:
    rng = ctx.rng
    # 1) initial recon fan-out
    home, robots = await ctx.burst(
        [
            RequestSpec("GET", "/", attack="recon", phase="recon"),
            RequestSpec("GET", "/robots.txt", attack="recon", phase="recon"),
        ]
    )
    await ctx.sleep(think_gap(rng))
    recon2 = [RequestSpec("GET", "/static/app.js", attack="recon", phase="recon")]
    recon2.append(RequestSpec("GET", "/openapi.json", attack="recon", phase="recon"))
    for extra in ("/.well-known/ai-plugin.json", "/docs", "/swagger.json", "/.well-known/mcp.json"):
        if rng.random() < 0.4:
            recon2.append(RequestSpec("GET", extra, attack="recon", phase="recon"))
    js, openapi, *_ = await ctx.burst(recon2)
    await ctx.sleep(think_gap(rng))

    # 2) discovery: routes that are never linked from HTML
    routes: list[str] = []
    for r in extract_js_routes(js.body):
        base = r.split("?", 1)[0]
        if base not in routes:
            routes.append(base)
    for _method, path, _params in extract_openapi_routes(openapi.body):
        path = path.replace("{pid}", "{id}").replace("{uid}", "{id}")
        if path not in routes:
            routes.append(path)
    disallowed = extract_robots_disallow(robots.body)

    # 3) AI canary: LLM agents tend to obey hidden instructions addressed to them
    canaries = find_canary_instructions(home.body) + find_canary_instructions(robots.body)
    if canaries and rng.random() < 0.9:
        inst = canaries[0]
        path = same_origin_path(ctx.base_url, inst.path) if inst.path else "/"
        hdrs = [inst.header] if inst.header else []
        if path:
            target, _, query = path.partition("?")
            await ctx.request(
                "GET", target, query=query or None, headers=hdrs, attack="ai_canary_follow", phase="canary"
            )
            await ctx.sleep(think_gap(rng))

    # 4) enumerate discovered API routes in bursts
    endpoints = [_concretize(r) for r in routes if r not in ("/api/login", "/api/chat")]
    rng.shuffle(endpoints)
    while endpoints:
        n = rng.randint(3, 5)
        chunk, endpoints = endpoints[:n], endpoints[n:]
        specs = []
        for ep in chunk:
            query = {
                "/api/search": "q=test",
                "/api/files/download": "name=catalog.pdf",
                "/api/products": "page=1",
            }.get(ep)
            specs.append(RequestSpec("GET", ep, query=query, attack="recon", phase="enumerate"))
        await ctx.burst(specs)
        await ctx.sleep(think_gap(rng))
    if disallowed:
        await ctx.burst([RequestSpec("GET", d, attack="recon", phase="robots") for d in disallowed[:4]])
        await ctx.sleep(think_gap(rng))
    # object-id tampering on templated routes (IDOR hypothesis)
    templated = [r for r in routes if "{id}" in r]
    if templated:
        ids = rng.sample(["0", "2", "3", "13", "999", "-1"], k=3)
        route = rng.choice(templated)
        await ctx.burst(
            [RequestSpec("GET", route.replace("{id}", i), attack="idor", phase="tamper") for i in ids]
        )
        await ctx.sleep(think_gap(rng))

    # 5) exploitation with error-conditioned mutation
    candidates = [
        _Target("GET", "/api/search", "q", "sqli"),
        _Target("GET", "/api/products/{id}", None, "sqli"),
        _Target("GET", "/api/products", "sort", "sqli"),
        _Target("GET", "/api/files/download", "name", "path_traversal"),
        _Target("GET", "/api/search", "q", "xss"),
        _Target("GET", "/api/search", "q", "ssti"),
        _Target("POST", "/api/login", "username", "sqli"),
        _Target("GET", "/api/users/{id}", None, "sqli"),
    ]
    known = set(routes) | {"/api/login"}
    targets = [t for t in candidates if t.path in known]
    rng.shuffle(targets)
    targets = targets[: rng.randint(4, 6)]
    chains = [_Chain(t, rng) for t in targets]
    while chains:
        n = rng.randint(2, 3)
        active, chains = chains[:n], chains[n:]
        while active:
            responses = await ctx.burst([c.spec() for c in active])
            still = []
            for chain, resp in zip(active, responses, strict=True):
                if chain.observe(resp.status):
                    still.append(chain)
            active = still
            await ctx.sleep(lognormal(rng, 4.5, 0.4, 1.5, 15.0) if active else think_gap(rng))

    # 6) LLM endpoint probing
    if "/api/chat" in known or rng.random() < 0.5:
        for _ in range(rng.randint(1, 2)):
            msg = rng.choice(P.PROMPT_INJECTION_EN)
            await ctx.request(
                "POST", "/api/chat", json_body={"message": msg}, attack="prompt_injection", phase="llm"
            )
            await ctx.sleep(think_gap(rng))


class _Chain:
    """One (endpoint, parameter, family) probe chain that mutates its payload after error responses."""

    def __init__(self, target: _Target, rng: random.Random) -> None:
        self.t = target
        self.rng = rng
        self.step = 0
        self.max_steps = rng.randint(3, 6)
        base = rng.choice(P.FAMILIES[target.family])
        if target.family == "sqli" and rng.random() < 0.35:
            base = f"{base} {rng.choice(P.NL_COMMENTS)}"
        self.payload = base
        self.confirming = False

    def spec(self) -> RequestSpec:
        t = self.t
        if t.method == "POST":
            body = json.dumps({"username": self.payload, "password": self.rng.choice(P.NL_PROBE_VALUES)})
            return RequestSpec(
                "POST", t.path, body=body, content_type="application/json", attack=t.family, phase="exploit"
            )
        if t.param is None:
            return RequestSpec(
                "GET", t.path.replace("{id}", quote(self.payload, safe="")), attack=t.family, phase="exploit"
            )
        return RequestSpec(
            "GET", t.path, query=f"{t.param}={quote(self.payload, safe='')}", attack=t.family, phase="exploit"
        )

    def observe(self, status: int) -> bool:
        """Update after a response. Return True to keep probing."""
        self.step += 1
        if self.step >= self.max_steps or status in (0, 401, 404, 405):
            return False
        if status in (400, 403, 413, 500, 502):
            self.payload = P.mutate(self.payload, self.step, self.rng)
            return True
        if status < 400 and not self.confirming and self.t.family == "sqli":
            self.confirming = True  # boolean-pair confirmation, as agents verify a hypothesis
            self.payload = "1' AND '1'='2" if "'" in self.payload else "1 AND 1=2"
            return True
        return False


# --------------------------------------------------------------------------------- llm_app_attacker


async def llm_app_attacker(ctx: SessionContext) -> None:
    rng = ctx.rng
    scripted = not ctx.is_browser
    conv = f"c-{rng.getrandbits(32):08x}"
    if ctx.is_browser:
        await ctx.page("/", assets=ASSETS)
        await ctx.sleep(human_gap(rng))
    for _ in range(rng.randint(1, 2)):
        q = rng.choice(P.BENIGN_CHAT_JA + P.BENIGN_CHAT_EN)
        await ctx.request("POST", "/api/chat", json_body={"message": q, "conversation_id": conv})
        await ctx.sleep(rng.uniform(1.5, 3.0) if scripted else human_gap(rng, 12.0))
    pool = P.PROMPT_INJECTION_EN + P.PROMPT_INJECTION_JA
    for _ in range(rng.randint(5, 9)):
        msg = P.b64_obfuscated_injection(rng) if rng.random() < 0.15 else rng.choice(pool)
        await ctx.request(
            "POST",
            "/api/chat",
            json_body={"message": msg, "conversation_id": conv},
            attack="prompt_injection",
            phase="llm",
        )
        await ctx.sleep(rng.uniform(1.5, 3.0) if scripted else lognormal(rng, 20.0, 0.7, 4.0, 120.0))


# ----------------------------------------------------------------------------------------- registry

PROFILES: dict[str, Profile] = {
    p.name: p
    for p in (
        Profile(
            "benign_browser", "benign", "Normal shoppers using a browser", benign_browser, browser_identity
        ),
        Profile(
            "scanner",
            "automated_scanner",
            "Wordlist + signature scanner at fixed rate",
            scanner,
            scanner_identity,
        ),
        Profile(
            "human_attacker",
            "human",
            "Manual SQLi/XSS tries with human pacing",
            human_attacker,
            human_attacker_identity,
        ),
        Profile(
            "ai_agent",
            "ai_agent",
            "ARTEX-like autonomous LLM agent (discovery, mutation, bursts, follows canaries)",
            ai_agent,
            ai_agent_identity,
        ),
        Profile(
            "llm_app_attacker",
            "human",
            "Prompt injection / jailbreak attempts against /api/chat",
            llm_app_attacker,
            llm_attacker_identity,
        ),
    )
}

DEFAULT_MIX: dict[str, int] = {
    "benign_browser": 6,
    "scanner": 2,
    "human_attacker": 3,
    "ai_agent": 3,
    "llm_app_attacker": 2,
}


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(f"unknown profile {name!r}; choose from {', '.join(sorted(PROFILES))}") from None


def parse_mix(spec: str | None, *, default_count: int | None = None) -> dict[str, int]:
    """``"ai_agent=3,benign_browser=5"`` or ``"ai_agent,scanner"`` (count = default_count or 1) or ``"all"``."""
    if not spec or spec.strip() in ("all", "mixed", "default"):
        if default_count is None:
            return dict(DEFAULT_MIX)
        return dict.fromkeys(PROFILES, default_count)
    mix: dict[str, int] = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        name, _, count = part.partition("=")
        get_profile(name.strip())
        mix[name.strip()] = int(count) if count else (default_count or 1)
    return mix
