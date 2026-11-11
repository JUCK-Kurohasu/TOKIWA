"""Side upstream for injection side-effect tests (localhost only)."""
import asyncio, gzip
from starlette.applications import Starlette
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route
PAGE = "<!doctype html><html><head><meta charset='utf-8'><title>t</title></head><body><p>hello</p></body></html>"
async def gz(req):
    return Response(gzip.compress(PAGE.encode()), media_type="text/html; charset=utf-8",
        headers={"content-encoding":"gzip","etag":'"v1"',"cache-control":"public, max-age=600","vary":"Accept-Encoding","last-modified":"Mon, 01 Jan 2024 00:00:00 GMT"})
async def plain(req):
    if req.headers.get("if-none-match") == '"v1"':
        return Response(status_code=304, headers={"etag":'"v1"'})
    return Response(PAGE, media_type="text/html; charset=utf-8", headers={"etag":'"v1"',"cache-control":"public, max-age=600"})
async def stream(req):
    async def gen():
        yield b"<!doctype html><html><head><title>s</title></head><body><p>first chunk (shell)</p>"
        for i in range(4):
            await asyncio.sleep(1.0)
            yield f"<p>chunk {i}</p>".encode()
        yield b"</body></html>"
    return StreamingResponse(gen(), media_type="text/html; charset=utf-8")
async def sjis(req):
    body = "<html><head><meta charset='shift_jis'></head><body><p>日本語のページ</p></body></html>".encode("shift_jis")
    return Response(body, headers={"content-type":"text/html"})
async def csp(req):
    return Response(PAGE, media_type="text/html; charset=utf-8", headers={"content-security-policy":"default-src 'self'; style-src 'self'"})
app = Starlette(routes=[Route("/gz", gz), Route("/plain", plain), Route("/stream", stream), Route("/sjis", sjis), Route("/csp", csp)])
