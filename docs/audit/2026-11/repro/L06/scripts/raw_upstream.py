"""Raw HTTP/1.1 upstream that logs exactly what it receives (per connection) and answers each request.
Paths: /html -> text/html with </body>; /gzip -> gzip html; /bigN -> N KiB html; /slowhtml -> chunked html slowly;
default -> JSON echo of request line + headers. Log: JSONL with conn id, raw head, body length."""
import asyncio, json, sys, time, gzip
PORT = int(sys.argv[1]); LOG = sys.argv[2]
cid = 0
def log(o):
    with open(LOG, "a") as f: f.write(json.dumps(o) + "\n")
async def handle(r, w):
    global cid; cid += 1; me = cid; seq = 0; buf = b""
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                d = await r.read(65536)
                if not d: return
                buf += d
            head, buf = buf.split(b"\r\n\r\n", 1)
            lines = head.split(b"\r\n"); reqline = lines[0].decode("latin-1")
            hdrs = [l.decode("latin-1") for l in lines[1:]]
            hl = {h.split(":",1)[0].strip().lower(): h.split(":",1)[1].strip() for h in hdrs if ":" in h}
            body = b""
            if "chunked" in hl.get("transfer-encoding","").lower():
                while True:
                    while b"\r\n" not in buf:
                        d = await r.read(65536)
                        if not d: return
                        buf += d
                    szl, buf = buf.split(b"\r\n", 1); sz = int(szl.split(b";")[0], 16)
                    while len(buf) < sz + 2:
                        d = await r.read(65536)
                        if not d: return
                        buf += d
                    body += buf[:sz]; buf = buf[sz+2:]
                    if sz == 0: break
            elif "content-length" in hl:
                n = int(hl["content-length"])
                while len(buf) < n:
                    d = await r.read(65536)
                    if not d: return
                    buf += d
                body, buf = buf[:n], buf[n:]
            seq += 1
            log({"conn": me, "seq": seq, "t": time.time(), "reqline": reqline, "headers": hdrs, "body_len": len(body), "body": body[:200].decode("latin-1")})
            path = reqline.split(" ")[1] if " " in reqline else "/"
            ctype = "application/json"; extra = ""
            if path.startswith("/html"):
                payload = b"<html><head><title>t</title></head><body><p>hello</p></body></html>"; ctype = "text/html; charset=utf-8"
            elif path.startswith("/gzip"):
                payload = gzip.compress(b"<html><body><p>gz</p></body></html>"); ctype = "text/html"; extra = "Content-Encoding: gzip\r\n"
            elif path.startswith("/big"):
                n = int(path[4:].split("?")[0] or 1000); payload = b"<html><body>" + b"A" * (n*1024) + b"</body></html>"; ctype = "text/html"
            elif path.startswith("/slowhtml"):
                w.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nServer: rawup\r\n\r\n")
                for i in range(int(path.split("=")[-1]) if "=" in path else 5):
                    c = f"<p>chunk {i} {time.time()}</p>".encode(); w.write(b"%x\r\n%s\r\n" % (len(c), c)); await w.drain(); await asyncio.sleep(1)
                c = b"</body></html>"; w.write(b"%x\r\n%s\r\n0\r\n\r\n" % (len(c), c)); await w.drain(); continue
            elif path.startswith("/hdr"):
                payload = b"ok"; extra = "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\nServer: rawup/1.0\r\n"
            else:
                payload = json.dumps({"conn": me, "seq": seq, "reqline": reqline, "headers": hdrs, "body_len": len(body)}).encode()
            if "Server:" not in extra: extra += "Server: rawup\r\n"
            w.write(f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(payload)}\r\n{extra}\r\n".encode() + payload)
            await w.drain()
    except Exception as e:
        log({"conn": me, "error": repr(e)})
    finally:
        w.close()
async def main():
    s = await asyncio.start_server(handle, "127.0.0.1", PORT)
    async with s: await s.serve_forever()
asyncio.run(main())
