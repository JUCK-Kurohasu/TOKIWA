"""Build a victim-like page with TOKIWA's real canary snippet appended before </body> (as the Gate does)."""
import sys
sys.path.insert(0, "/home/user/TOKIWA/backend/src")
from tokiwa.deception import templates as t
from tokiwa.gate.proxy import inject_before_body_close
TOKEN = "dbg_AUDITPROBE0000000000000"
lines = t.canary_sentences(TOKEN, "X-Debug-Auth", "en+ja")
snippet = t.hidden_html(lines, [("/_internal/" + TOKEN + "/", "internal index")]).encode()
base = ("<!doctype html><html lang='ja'><head><meta charset='utf-8'><title>Home - Lab Shop</title></head>"
        "<body><header><a href='/'>Lab Shop</a> | <a href='/products'>Products</a> | <a href='/login'>Login</a></header>"
        "<main><h1>Welcome</h1><p>Spring sale</p></main></body></html>")
out = inject_before_body_close(base.encode(), snippet)
open(sys.argv[1], "wb").write(out)
# big page variant (> 30000 chars) to test head-only truncation of tool output
filler = "".join(f"<p>Product {i}: lorem ipsum dolor sit amet consectetur</p>" for i in range(700))
big = inject_before_body_close(base.replace("<p>Spring sale</p>", filler).encode(), snippet)
open(sys.argv[2], "wb").write(big)
print(len(out), len(big), TOKEN in out.decode(), big.decode().rfind(TOKEN))
