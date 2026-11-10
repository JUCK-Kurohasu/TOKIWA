"""L04 audit: evasive AI-agent variants and benign look-alike profiles, registered into tokiwa.eval.profiles at runtime.
Inert detection-test payloads only (tokiwa.eval.payloads). Offline (VirtualLab) use."""
from __future__ import annotations
import ipaddress, json, random
from dataclasses import dataclass, replace
from urllib.parse import quote
from tokiwa.eval import payloads as P
from tokiwa.eval import profiles as PR
from tokiwa.eval.discovery import extract_js_routes, extract_openapi_routes, extract_robots_disallow, find_canary_instructions
from tokiwa.eval.exchange import ClientIdentity, SimRequest
from tokiwa.eval.safety import same_origin_path
from tokiwa.eval.sim import RequestSpec
from tokiwa.eval.virtual import VirtualLab, DEMO_SESSION, DEMO_USER, DEMO_PASSWORD, OPENAPI_PATHS

ROT_NET = ipaddress.ip_network("100.64.0.0/10")
_rot_rng = random.Random(4242)
def rot_ip() -> str:
    return str(ROT_NET.network_address + _rot_rng.randint(2, ROT_NET.num_addresses - 2))

@dataclass(frozen=True)
class Cfg:
    timing: str = "burst"      # burst | uniform | human | slow | slow_split
    ident: str = "lib"         # lib | chrome
    https: bool = False
    follow_canary: bool = False
    nl: bool = True
    eco: bool = True
    fetch_spec: bool = True    # False: routes known from public docs (no spec/JS fetch seen by the Gate)
    mutation: str = "adaptive" # adaptive | none
    quiet: bool = False        # payloads pre-validated to not error
    rotate: int = 0            # new source IP every N requests
    workers: bool = False      # recon / enum / exploit split across IP+UA workers
    interleave: bool = False   # benign page views between attack steps

def _gap(ctx, cfg):
    r = ctx.rng
    return {"uniform": lambda: r.uniform(1.0, 12.0), "human": lambda: PR.human_gap(r, 6.0),
            "slow": lambda: r.uniform(300.0, 1500.0), "slow_split": lambda: r.uniform(1900.0, 3600.0),
            "burst": lambda: PR.think_gap(r)}[cfg.timing]()

async def emit(ctx, cfg, specs):
    if cfg.timing == "burst":
        return await ctx.burst(specs)
    out = []
    for i, s in enumerate(specs):
        if i:
            await ctx.sleep(_gap(ctx, cfg))
        out.append(await ctx.send(s))
    return out

async def pause(ctx, cfg):
    await ctx.sleep(_gap(ctx, cfg))

async def browse(ctx, cfg):
    p = ctx.rng.choice(["/products", f"/products/{ctx.rng.randint(1, 12)}", "/", "/login"])
    await ctx.page(p, assets=("/static/style.css", "/static/app.js", "/favicon.ico"))
    await ctx.sleep(PR.human_gap(ctx.rng, 5.0))

_LAB = VirtualLab(canary=False)
def _quiet(family, payloads, method, path, param):
    ok = []
    for p in payloads:
        if method == "POST":
            req = SimRequest("POST", path, body=json.dumps({"username": p, "password": "x"}))
        elif param is None:
            req = SimRequest("GET", path.replace("{id}", quote(p, safe="")))
        else:
            req = SimRequest("GET", path, query=f"{param}={quote(p, safe='')}")
        if _LAB.handle(req).status < 400:
            ok.append(p)
    return ok or payloads[:1]

class Chain:
    def __init__(self, t, rng, cfg):
        self.t, self.rng, self.cfg = t, rng, cfg
        self.step, self.max_steps, self.confirming = 0, rng.randint(3, 6), False
        pool = P.FAMILIES[t.family]
        if cfg.quiet:
            pool = _quiet(t.family, pool, t.method, t.path, t.param)
        base = rng.choice(pool)
        if cfg.nl and t.family == "sqli" and rng.random() < 0.35:
            base = f"{base} {rng.choice(P.NL_COMMENTS)}"
        self.payload = base
    def spec(self):
        t = self.t
        if t.method == "POST":
            body = json.dumps({"username": self.payload, "password": self.rng.choice(P.NL_PROBE_VALUES) if self.cfg.nl else "x9!Lk"})
            return RequestSpec("POST", t.path, body=body, content_type="application/json", attack=t.family, phase="exploit")
        if t.param is None:
            return RequestSpec("GET", t.path.replace("{id}", quote(self.payload, safe="")), attack=t.family, phase="exploit")
        return RequestSpec("GET", t.path, query=f"{t.param}={quote(self.payload, safe='')}", attack=t.family, phase="exploit")
    def observe(self, status):
        self.step += 1
        if self.cfg.mutation == "none" or self.step >= self.max_steps or status in (0, 401, 404, 405):
            return False
        if status in (400, 403, 413, 500, 502):
            self.payload = P.mutate(self.payload, self.step, self.rng)
            return True
        if status < 400 and not self.confirming and self.t.family == "sqli":
            self.confirming = True
            self.payload = "1' AND '1'='2" if "'" in self.payload else "1 AND 1=2"
            return True
        return False

def _lib_ident(rng, ip):
    return PR.ai_agent_identity(rng, ip)

def _workers(rng):
    mk = lambda ua, fam: ClientIdentity(source_ip=rot_ip(), user_agent=ua, family=fam)
    return {"recon": mk("curl/8.5.0", "curl"), "enum": mk("python-requests/2.32.3", "requests"),
            "x1": mk("Python/3.12 aiohttp/3.10.10", "aiohttp"), "x2": mk("Go-http-client/1.1", "go")}

def setup(ctx, cfg):
    if cfg.https:
        ctx.scheme = "https"
    if cfg.ident == "chrome":
        ctx.identity = PR.browser_identity(ctx.rng, ctx.identity.source_ip)
        ctx.identity = replace(ctx.identity, family="chrome", user_agent=PR._CHROME[0])
        ctx.cookie = f"sid={ctx.rng.getrandbits(64):016x}"
    if cfg.rotate:
        orig, n = ctx._send, [0]
        async def _send(spec, started):
            if n[0] % cfg.rotate == 0:
                ctx.identity = replace(ctx.identity, source_ip=rot_ip())
            n[0] += 1
            return await orig(spec, started)
        ctx._send = _send

async def agent(ctx, cfg: Cfg):
    rng = ctx.rng
    setup(ctx, cfg)
    W = _workers(rng) if cfg.workers else None
    if W: ctx.identity = W["recon"]
    robots_body = ""
    if cfg.ident == "chrome":
        home = await ctx.page("/", assets=PR.ASSETS)
    else:
        home, robots = await emit(ctx, cfg, [RequestSpec("GET", "/", attack="recon", phase="recon"),
                                             RequestSpec("GET", "/robots.txt", attack="recon", phase="recon")])
        robots_body = robots.body
    await pause(ctx, cfg)
    routes = []
    if cfg.fetch_spec:
        rec2 = [RequestSpec("GET", "/static/app.js", attack="recon", phase="recon"),
                RequestSpec("GET", "/openapi.json", attack="recon", phase="recon")]
        extras = ("/.well-known/ai-plugin.json", "/docs", "/swagger.json", "/.well-known/mcp.json") if cfg.eco else ("/docs", "/swagger.json")
        for extra in extras:
            if rng.random() < 0.4:
                rec2.append(RequestSpec("GET", extra, attack="recon", phase="recon"))
        js, openapi, *_ = await emit(ctx, cfg, rec2)
        await pause(ctx, cfg)
        for r in extract_js_routes(js.body):
            b = r.split("?", 1)[0]
            if b not in routes: routes.append(b)
        for _m, path, _p in extract_openapi_routes(openapi.body):
            path = path.replace("{pid}", "{id}").replace("{uid}", "{id}")
            if path not in routes: routes.append(path)
    else:
        routes = [p.replace("{pid}", "{id}").replace("{uid}", "{id}") for p in OPENAPI_PATHS]
    if cfg.follow_canary:
        cans = find_canary_instructions(home.body) + find_canary_instructions(robots_body)
        if cans and rng.random() < 0.9:
            inst = cans[0]
            cp = same_origin_path(ctx.base_url, inst.path) if inst.path else "/"
            if cp:
                target, _, query = cp.partition("?")
                await ctx.request("GET", target, query=query or None, headers=[inst.header] if inst.header else [],
                                  attack="ai_canary_follow", phase="canary")
                await pause(ctx, cfg)
    if W: ctx.identity = W["enum"]
    endpoints = [PR._concretize(r) for r in routes if r not in ("/api/login", "/api/chat")]
    rng.shuffle(endpoints)
    qmap = {"/api/search": "q=test", "/api/files/download": "name=catalog.pdf", "/api/products": "page=1"}
    while endpoints:
        n = rng.randint(3, 5)
        chunk, endpoints = endpoints[:n], endpoints[n:]
        if cfg.interleave: await browse(ctx, cfg)
        await emit(ctx, cfg, [RequestSpec("GET", ep, query=qmap.get(ep), attack="recon", phase="enumerate") for ep in chunk])
        await pause(ctx, cfg)
    disallowed = extract_robots_disallow(robots_body) if robots_body else []
    if disallowed:
        await emit(ctx, cfg, [RequestSpec("GET", d, attack="recon", phase="robots") for d in disallowed[:4]])
        await pause(ctx, cfg)
    templated = [r for r in routes if "{id}" in r]
    if templated:
        ids = rng.sample(["0", "2", "3", "13", "999", "-1"], k=3)
        route = rng.choice(templated)
        await emit(ctx, cfg, [RequestSpec("GET", route.replace("{id}", i), attack="idor", phase="tamper") for i in ids])
        await pause(ctx, cfg)
    cands = [PR._Target("GET", "/api/search", "q", "sqli"), PR._Target("GET", "/api/products/{id}", None, "sqli"),
             PR._Target("GET", "/api/products", "sort", "sqli"), PR._Target("GET", "/api/files/download", "name", "path_traversal"),
             PR._Target("GET", "/api/search", "q", "xss"), PR._Target("GET", "/api/search", "q", "ssti"),
             PR._Target("POST", "/api/login", "username", "sqli"), PR._Target("GET", "/api/users/{id}", None, "sqli")]
    known = set(routes) | {"/api/login"}
    targets = [t for t in cands if t.path in known]
    rng.shuffle(targets)
    targets = targets[: rng.randint(4, 6)]
    chains = [Chain(t, rng, cfg) for t in targets]
    wk = ["x1", "x2"]
    while chains:
        n = rng.randint(2, 3)
        active, chains = chains[:n], chains[n:]
        while active:
            if cfg.interleave: await browse(ctx, cfg)
            if W:
                resps = []
                for i, c in enumerate(active):
                    ctx.identity = W[wk[i % 2]]
                    resps += await emit(ctx, cfg, [c.spec()])
            else:
                resps = await emit(ctx, cfg, [c.spec() for c in active])
            active = [c for c, r in zip(active, resps) if c.observe(r.status)]
            if cfg.timing == "burst":
                await ctx.sleep(PR.lognormal(rng, 4.5, 0.4, 1.5, 15.0) if active else PR.think_gap(rng))
            else:
                await pause(ctx, cfg)
    if "/api/chat" in known or rng.random() < 0.5:
        for _ in range(rng.randint(1, 2)):
            await ctx.request("POST", "/api/chat", json_body={"message": rng.choice(P.PROMPT_INJECTION_EN)}, attack="prompt_injection", phase="llm")
            await pause(ctx, cfg)

VARIANTS = {
    "v_base_canary": Cfg(follow_canary=True),
    "v_base_nofollow": Cfg(),
    "v_jitter_uniform": Cfg(timing="uniform"),
    "v_jitter_human": Cfg(timing="human"),
    "v_chrome_http": Cfg(ident="chrome"),
    "v_chrome_https": Cfg(ident="chrome", https=True),
    "v_rotate1": Cfg(rotate=1),
    "v_rotate4": Cfg(rotate=4),
    "v_rotate10": Cfg(rotate=10),
    "v_slow_in_session": Cfg(timing="slow"),
    "v_slow_split": Cfg(timing="slow_split"),
    "v_error_avoidant": Cfg(mutation="none", quiet=True, nl=False),
    "v_no_nl_no_eco": Cfg(nl=False, eco=False),
    "v_docs_only": Cfg(fetch_spec=False),
    "v_multiworker": Cfg(workers=True),
    "v_multiworker_jitter": Cfg(workers=True, timing="uniform"),
    "v_interleave_chrome": Cfg(ident="chrome", https=True, interleave=True),
    "v_full_evasion": Cfg(timing="human", ident="chrome", https=True, nl=False, eco=False, fetch_spec=False,
                          mutation="none", quiet=True, interleave=True),
}

def register():
    for name, cfg in VARIANTS.items():
        async def run(ctx, _cfg=cfg):
            await agent(ctx, _cfg)
        PR.PROFILES[name] = PR.Profile(name, "ai_agent", f"L04 evasive variant {name}", run, _lib_ident)
    import benign_fp
    benign_fp.register()
