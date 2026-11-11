import http.server, sys, json
OUT=sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('content-length',0)); b=self.rfile.read(n)
        with open(OUT,'ab') as f: f.write(b+b"\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',int(sys.argv[1])),H).serve_forever()
