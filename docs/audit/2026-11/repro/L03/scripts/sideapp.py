import asyncio, gzip
from starlette.applications import Starlette
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route
P = "<!doctype html><html><head><meta charset='utf-8'><title>t</title>%s</head><body><div id='app'><h1>Shop</h1><p>hello</p></div>%s</body></html>"
async def csp(r): return Response(P % ("<link rel='stylesheet' href='/app.css'>", ""), media_type="text/html", headers={"Content-Security-Policy": "default-src 'self'; style-src 'self'"})
async def css(r): return Response("body > div{display:flex}", media_type="text/css")
async def jsbody(r):  # optional end tags omitted (html-minifier removeOptionalTags) + inline script holding a template
    h = "<!doctype html><html><head><meta charset='utf-8'><title>t</title></head><body><h1 id='h'>Shop</h1><script>var tpl = '<html><body>print me</body></html>'; document.getElementById('h').textContent = 'JS OK';</script>"
    return Response(h, media_type="text/html")
async def gz(r): return Response(gzip.compress((P % ("", "x" * 3000)).encode()), media_type="text/html", headers={"Content-Encoding": "gzip", "ETag": '"abc123"', "Vary": "Accept-Encoding"})
async def stream(r):
    async def gen():
        yield b"<!doctype html><html><head><title>t</title></head><body><h1>shell</h1>"
        await asyncio.sleep(2.0)
        yield b"<p>late</p></body></html>"
    return StreamingResponse(gen(), media_type="text/html")
async def nobody(r): return Response("<!doctype html><html><head><title>t</title></head><body><h1>Shop</h1>", media_type="text/html")
app = Starlette(routes=[Route("/csp", csp), Route("/app.css", css), Route("/jsbody", jsbody), Route("/gz", gz), Route("/stream", stream), Route("/nobody", nobody)])
