import socket, sys, json, os, time
PORT=int(sys.argv[1]); LOG=sys.argv[2]
def raw(name, payload, wait=2.0):
    n0=sum(1 for _ in open(LOG))
    s=socket.create_connection(("127.0.0.1",PORT)); s.settimeout(wait); s.sendall(payload); d=b""
    try:
        while True:
            c=s.recv(65536)
            if not c: break
            d+=c
    except Exception: pass
    s.close(); time.sleep(0.2)
    up=[json.loads(l) for l in open(LOG).read().splitlines()[n0:]]
    st=[l.decode('latin-1') for l in d.split(b"\r\n") if l.startswith(b"HTTP/")]
    print(f"{name:22} resp={st} upstream={[ (u.get('reqline'), u.get('body_len')) for u in up]}")
H=b"Host: x\r\n"
raw("CL.TE", b"POST /a HTTP/1.1\r\n"+H+b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smug HTTP/1.1\r\nHost: x\r\n\r\n")
raw("TE.CL", b"POST /a HTTP/1.1\r\n"+H+b"Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\nGET /smu\r\n0\r\n\r\n")
raw("dupCL", b"POST /a HTTP/1.1\r\n"+H+b"Content-Length: 0\r\nContent-Length: 30\r\n\r\nGET /smug HTTP/1.1\r\nHost: x\r\n\r\n")
raw("TE-obf-space", b"POST /a HTTP/1.1\r\n"+H+b"Transfer-Encoding : chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n")
raw("TE-xchunked", b"POST /a HTTP/1.1\r\n"+H+b"Transfer-Encoding: xchunked\r\nContent-Length: 4\r\n\r\nabcd")
raw("TE-chunked,id", b"POST /a HTTP/1.1\r\n"+H+b"Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n")
raw("TE-tab", b"POST /a HTTP/1.1\r\n"+H+b"Transfer-Encoding:\tchunked\r\n\r\n0\r\n\r\n")
raw("chunk-ext", b"POST /a HTTP/1.1\r\n"+H+b"Transfer-Encoding: chunked\r\n\r\n4;x=y\r\nabcd\r\n0\r\n\r\n")
raw("LF-only", b"GET /lf HTTP/1.1\n"+b"Host: x\n\nGET /lf2 HTTP/1.1\nHost: x\n\n")
raw("pipeline3", b"GET /p1 HTTP/1.1\r\n"+H+b"\r\nGET /p2 HTTP/1.1\r\n"+H+b"\r\nGET /.env HTTP/1.1\r\n"+H+b"Connection: close\r\n\r\n")
raw("CL-nonnum", b"POST /a HTTP/1.1\r\n"+H+b"Content-Length: +4\r\n\r\nabcd")
raw("http1.0-ka", b"GET /h10 HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET /h10b HTTP/1.0\r\n\r\n")
raw("expect100", b"POST /e HTTP/1.1\r\n"+H+b"Expect: 100-continue\r\nContent-Length: 4\r\n\r\nabcd")
raw("obsfold", b"GET /fold HTTP/1.1\r\n"+H+b"X-A: a\r\n b\r\n\r\n")
