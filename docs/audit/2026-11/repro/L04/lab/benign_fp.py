"""L04 audit: benign profiles likely to be mis-attributed as AI agents (all labelled actor=benign)."""
from __future__ import annotations
from urllib.parse import quote
from tokiwa.eval import payloads as P
from tokiwa.eval import profiles as PR
from tokiwa.eval.exchange import ClientIdentity
from tokiwa.eval.sim import RequestSpec
from tokiwa.eval.virtual import DEMO_SESSION, DEMO_USER, DEMO_PASSWORD

def ident(ua, fam="ua"):
    return lambda rng, ip: ClientIdentity(source_ip=ip, user_agent=ua, family=fam, accept_language="ja-JP,ja;q=0.9")

PAGES = ["/", "/products", "/login"] + [f"/products/{i}" for i in range(1, 13)]
APIS = ["/api/products", "/api/products/{id}", "/api/search", "/api/orders"]

def _api_spec(rng, ep):
    if ep == "/api/products": return RequestSpec("GET", ep, query=f"page={rng.randint(1,3)}")
    if ep == "/api/products/{id}": return RequestSpec("GET", f"/api/products/{rng.randint(1,12)}")
    if ep == "/api/search": return RequestSpec("GET", ep, query="q=" + quote(rng.choice(P.BENIGN_SEARCH)))
    return RequestSpec("GET", ep)

async def mobile_app(ctx):   # okhttp app: screen open -> parallel API calls, then the user reads
    rng = ctx.rng
    ctx.auth = f"Bearer {DEMO_SESSION}"
    for _ in range(rng.randint(5, 10)):
        await ctx.burst([_api_spec(rng, ep) for ep in rng.sample(APIS, k=rng.randint(2, 4))])
        await ctx.sleep(PR.lognormal(rng, 8.0, 0.6, 2.0, 60.0))

async def sdk_poller(ctx):   # integration polling two endpoints every 30 s
    rng = ctx.rng
    for _ in range(rng.randint(20, 40)):
        await ctx.burst([RequestSpec("GET", "/api/products", query="page=1"), RequestSpec("GET", "/health")])
        await ctx.sleep(30.0 + rng.uniform(-0.2, 0.2))

async def uptime_monitor(ctx):  # UptimeRobot-like keyword check every 60 s
    for _ in range(ctx.rng.randint(15, 30)):
        await ctx.request("GET", "/", kind="document")
        await ctx.sleep(60.0)

async def multi_check_monitor(ctx):  # synthetic monitor: spec contract check + 3 endpoints every 60 s
    rng = ctx.rng
    for _ in range(rng.randint(10, 20)):
        await ctx.burst([RequestSpec("GET", "/openapi.json"), RequestSpec("GET", "/api/products", query="page=1"),
                         RequestSpec("GET", "/api/products/1"), RequestSpec("GET", "/health")])
        await ctx.sleep(60.0 + rng.uniform(-1, 1))

async def ci_contract_test(ctx):  # Dredd/Schemathesis-examples style: spec then every route with valid examples
    rng = ctx.rng
    spec = await ctx.request("GET", "/openapi.json")
    await ctx.sleep(rng.uniform(0.3, 1.5))
    for p in ["/api/products", "/api/products/1", "/api/search", "/api/orders", "/api/users/1", "/api/files/download", "/api/admin/export"]:
        q = {"/api/products": "page=1&limit=10&sort=name", "/api/search": "q=mug", "/api/files/download": "name=catalog.pdf"}.get(p)
        await ctx.request("GET", p, query=q)
        await ctx.sleep(rng.uniform(0.05, 0.4))
    await ctx.request("POST", "/api/login", json_body={"username": DEMO_USER, "password": DEMO_PASSWORD})

async def heavy_user(ctx):  # power user with tabs opened in bursts
    rng = ctx.rng
    ctx.cookie = f"sid={rng.getrandbits(64):016x}"
    await ctx.page("/", assets=PR.ASSETS)
    for _ in range(rng.randint(6, 12)):
        await ctx.sleep(PR.lognormal(rng, 3.0, 0.5, 0.8, 30.0))
        for _ in range(rng.randint(1, 4)):
            await ctx.page(f"/products/{rng.randint(1, 12)}", assets=("/static/app.js",))
        await ctx.request("GET", "/api/search", query="q=" + quote(rng.choice(P.BENIGN_SEARCH)))

async def text_browser(ctx):  # Lynx (accessibility / text-mode)
    rng = ctx.rng
    for p in rng.sample(PAGES, k=rng.randint(6, 12)):
        await ctx.request("GET", p, kind="document", referer=ctx._last_url)
        await ctx.sleep(PR.human_gap(rng, 9.0))

async def link_checker(ctx):  # W3C-checklink style: robots + sitemap, then every link with small concurrency
    rng = ctx.rng
    await ctx.burst([RequestSpec("GET", "/robots.txt"), RequestSpec("GET", "/sitemap.xml")])
    await ctx.sleep(rng.uniform(1.0, 2.0))
    links = PAGES + ["/static/style.css", "/static/app.js", "/old-page", "/products/99", "/docs"]
    rng.shuffle(links)
    while links:
        chunk, links = links[:4], links[4:]
        await ctx.burst([RequestSpec("GET", l, kind="document") for l in chunk])
        await ctx.sleep(rng.uniform(1.0, 3.0))   # politeness delay

async def search_crawler(ctx):  # Googlebot-like
    rng = ctx.rng
    await ctx.request("GET", "/robots.txt")
    await ctx.sleep(rng.uniform(1, 5))
    await ctx.request("GET", "/sitemap.xml")
    for p in rng.sample(PAGES, k=rng.randint(8, 14)):
        await ctx.sleep(PR.lognormal(rng, 6.0, 0.7, 1.0, 60.0))
        await ctx.request("GET", p, kind="document")

async def ai_crawler(ctx):  # GPTBot/ClaudeBot/PerplexityBot-like: robots, llms.txt, sitemap, pages in small parallel batches
    rng = ctx.rng
    await ctx.burst([RequestSpec("GET", "/robots.txt"), RequestSpec("GET", "/llms.txt")])
    await ctx.sleep(rng.uniform(2, 8))
    await ctx.request("GET", "/sitemap.xml")
    pages = rng.sample(PAGES, k=rng.randint(9, 15))
    while pages:
        chunk, pages = pages[:rng.randint(2, 4)], pages[4:]
        await ctx.sleep(PR.lognormal(rng, 6.0, 0.5, 1.5, 40.0))
        await ctx.burst([RequestSpec("GET", p, kind="document") for p in chunk])

async def ai_assistant_research(ctx):  # user-triggered ChatGPT-User / Claude-User doing deep research on the shop
    rng = ctx.rng
    await ctx.burst([RequestSpec("GET", "/"), RequestSpec("GET", "/robots.txt")])
    if rng.random() < 0.5:
        await ctx.sleep(PR.think_gap(rng))
        await ctx.burst([RequestSpec("GET", "/llms.txt"), RequestSpec("GET", "/openapi.json")])
    for _ in range(rng.randint(3, 6)):
        await ctx.sleep(PR.think_gap(rng))
        specs = [RequestSpec("GET", f"/products/{rng.randint(1, 12)}") for _ in range(rng.randint(1, 3))]
        if rng.random() < 0.5:
            specs.append(_api_spec(rng, rng.choice(["/api/products", "/api/search", "/api/products/{id}"])))
        await ctx.burst(specs)

async def browser_agent(ctx):  # user's browsing agent in real Chrome (Operator / browser-use with Chrome)
    rng = ctx.rng
    ctx.cookie = f"sid={rng.getrandbits(64):016x}"
    await ctx.page("/", assets=PR.ASSETS)
    for _ in range(rng.randint(5, 10)):
        await ctx.sleep(PR.think_gap(rng))
        if rng.random() < 0.6:
            await ctx.page(f"/products/{rng.randint(1, 12)}", assets=("/static/app.js", "/static/style.css"))
        else:
            await ctx.request("GET", "/api/search", query="q=" + quote(rng.choice(P.BENIGN_SEARCH)))

async def api_script(ctx):  # employee's python script calling the API with sleeps (behind the corporate NAT)
    rng = ctx.rng
    ctx.auth = f"Bearer {DEMO_SESSION}"
    for _ in range(rng.randint(6, 12)):
        await ctx.burst([_api_spec(rng, ep) for ep in rng.sample(APIS, k=rng.randint(1, 3))])
        await ctx.sleep(PR.lognormal(rng, 5.0, 0.4, 1.5, 30.0))

FP = {
    "fp_mobile_app": (mobile_app, ident("okhttp/4.12.0", "go")),
    "fp_sdk_poller": (sdk_poller, ident("Go-http-client/1.1", "go")),
    "fp_uptime_monitor": (uptime_monitor, ident("Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)", "go")),
    "fp_multi_check_monitor": (multi_check_monitor, ident("Checkly/1.0 (https://www.checklyhq.com)", "httpx")),
    "fp_ci_contract_test": (ci_contract_test, ident("python-requests/2.32.3", "requests")),
    "fp_heavy_user": (heavy_user, PR.browser_identity),
    "fp_text_browser": (text_browser, ident("Lynx/2.9.0dev.12 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/3.7.8", "ua")),
    "fp_link_checker": (link_checker, ident("W3C-checklink/5.0.0 libwww-perl/6.77", "requests")),
    "fp_googlebot": (search_crawler, ident("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "go")),
    "fp_gptbot": (ai_crawler, ident("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", "go")),
    "fp_claudebot": (ai_crawler, ident("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "go")),
    "fp_perplexitybot": (ai_crawler, ident("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)", "go")),
    "fp_chatgpt_user": (ai_assistant_research, ident("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", "go")),
    "fp_claude_user": (ai_assistant_research, ident("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)", "httpx")),
    "fp_browser_agent_chrome": (browser_agent, PR.browser_identity),
    "fp_browser_agent_headless": (browser_agent, ident("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/130.0.0.0 Safari/537.36", "chrome")),
    "fp_api_script": (api_script, ident("python-requests/2.32.3", "requests")),
}

def register():
    for name, (run, idf) in FP.items():
        PR.PROFILES[name] = PR.Profile(name, "benign", f"L04 benign look-alike {name}", run, idf)
