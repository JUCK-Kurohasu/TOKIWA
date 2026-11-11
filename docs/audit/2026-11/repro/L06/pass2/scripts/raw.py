import socket,sys,time
def raw(port,payload,wait=1.5):
    s=socket.create_connection(("127.0.0.1",port)); s.settimeout(wait); s.sendall(payload); d=b""
    try:
        while True:
            c=s.recv(65536)
            if not c: break
            d+=c
    except Exception: pass
    s.close(); return d
if __name__=="__main__":
    port=int(sys.argv[1]); p=sys.argv[2].encode().decode("unicode_escape").encode("latin-1")
    print(raw(port,p).decode("latin-1")[:1500])
