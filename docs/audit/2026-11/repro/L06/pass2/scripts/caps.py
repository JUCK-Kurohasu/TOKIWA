import socket,gzip,sys,time
P=int(sys.argv[1])
def send(req):
    s=socket.create_connection(("127.0.0.1",P)); s.settimeout(3); s.sendall(req); d=b""
    try:
        while True:
            c=s.recv(65536)
            if not c: break
            d+=c
    except Exception: pass
    s.close(); return d.split(b"\r\n",1)[0].decode()
UA=b"User-Agent: sqlmap/1.8.2#stable (https://sqlmap.org)\r\n"
REF=b"Referer: http://x/?id=1' UNION SELECT username,password FROM users--\r\n"
pad=b"".join(b"X-Pad-%d: a\r\n"%i for i in range(64))
print("ctl-hdr", send(b"GET /capctl1 HTTP/1.1\r\nHost: x\r\n"+UA+REF+b"Connection: close\r\n\r\n"))
print("pad-hdr", send(b"GET /cappad1 HTTP/1.1\r\nHost: x\r\n"+pad+UA+REF+b"Connection: close\r\n\r\n"))
body=b"username=admin' OR '1'='1'-- &password=x' UNION SELECT password FROM users--"
print("ctl-body", send(b"POST /capctl2 HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"%len(body)+body))
gz=gzip.compress(body)
print("gz-body", send(b"POST /capgz2 HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"%len(gz)+gz))
