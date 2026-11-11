# L06 pass2 NOTES
ports: server 21600, victim 21601, rawup 21602, gateA(trust off->victim) 21603, gateR(trust off->rawup) 21604, gateT(trust on->rawup) 21605
## done
- read gate source (uvicorn 0.54 + httptools 0.9 server; httpx 0.28.1/httpcore 1.0.9/h11 0.16 upstream client)
## in progress
- starting stack
## next
- smuggling tests, forwarded header passthrough, method override, TLS link, absolute-form/CONNECT
- smuggling battery (scripts/smuggle.py on gateR): CL.TE/TE.CL/dupCL/TE obfuscation/bare LF/obs-fold/CL '+4' all 400 by httptools; chunk-ext/Expect/pipelining fine; upstream re-serialized by h11 -> no desync found (negative result)
- absolute-form: host part dropped, path forwarded, Host header kept -> no open proxy/SSRF; CONNECT and '@host' -> 400; fragment stripped
- filed L06-06 (Forwarded/X-Real-IP passthrough), L06-07 (X-Original-URL), L06-08 (gate<->server TLS/policy integrity, fake policy server PoC)
## next: httpx default UA/Accept injection; IPv6 /64 rotation + rate limit per-IP; XFF w/ port; ratelimit key; HEAD/body mismatch; gate-generated response headers; token in argv
- duplicate headers: capture joins with ', ' (cookie '; ') -> no first/last mismatch (negative). Header COUNT cap 64 -> L06-09. gzip req body -> L06-10.
- filed L06-09..13 (header cap, gzip body, CIDR/IPv6 rate-limit per address, no-store on generic 404/502/504, --token argv + host sensor)
## next: httpx default UA/Accept injection (low), cleanup PIDs, final report
- filed L06-14 (httpx default UA/Accept injected upstream). Amended L06-08 title/evidence.
- all processes stopped (server, victim, rawup, gateA/R/T/M, fakepolicy, tlssrv); gate.token deleted
## not tested: real CDN caching of 404 (L06-12), upstream apps honoring X-Original-URL / gzip bodies (Express) end-to-end, host sensor e2e capturing gate cmdline (L06-13), h2c/WebSocket beyond code reading (upgrade stripped as hop-by-hop; WS -> 501)
## DONE
