import http.server,ssl,json,sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b=json.dumps({"seen_token": bool(self.headers.get("X-Tokiwa-Token"))}).encode(); self.send_response(503); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): sys.stderr.write("REQ %s token=%s\n"%(self.path, bool(self.headers.get("X-Tokiwa-Token"))))
s=http.server.HTTPServer(("127.0.0.1",21610),H); c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain("ca.pem","ca.key"); s.socket=c.wrap_socket(s.socket,server_side=True); s.serve_forever()
