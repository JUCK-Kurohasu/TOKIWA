import sys, time
sys.path.insert(0, sys.argv[1])
from harness import *
from tokiwa.detect.web_common import registered_patterns
from tokiwa.detect.sigma import validate_rule
# 1) detector regexes vs adversarial 8192-char inputs
seeds = ["'", "<", "a=", "../", "${", "{{", " or ", "%", "a", "1 ", "<a ", "\\", "$(", ";", "/*", "|", "&#", "select ", "union ", "o:1:", "rO0", "http://", "a.", "-", " ", "x(", "=", ",", "\"", "@", "a1", "<!", "]", "file:", "eval("]
worst = []
pats = registered_patterns()
for name, p in pats:
    m = 0; ms = ""
    for sd in seeds:
        s = (sd * (8192 // len(sd) + 1))[:8192]
        t = time.perf_counter(); p.search(s); d = time.perf_counter() - t
        if d > m: m, ms = d, sd
    worst.append((m, name, ms))
worst.sort(reverse=True)
print("patterns:", len(pats)); [print(f"{w*1000:8.1f} ms  {n}  seed={s!r}") for w, n, s in worst[:8]]
# end-to-end: full engine on worst-case events
for sd in [worst[0][2], worst[1][2], "'"]:
    s = (sd * 9000)[:8192]
    t = time.perf_counter(); run([direct_event("/a?q=x", method="POST", ct="text/plain", body=s, headers={"user-agent": s[:2048], "x-a": s[:2048]})]); print(f"engine one event seed={sd!r}: {time.perf_counter()-t:.3f}s")
# 2) sigma |re ReDoS acceptance
rule = """title: redos test
logsource: {category: webserver}
detection:
  sel:
    cs-user-agent|re: '^(a+)+$'
  condition: sel
level: low
"""
print("validate:", validate_rule(rule)[:2])
import re
for n in (20, 24, 26):
    t = time.perf_counter(); re.search(r'^(a+)+$', "a" * n + "!"); print(f"(a+)+$ n={n}: {time.perf_counter()-t:.2f}s")
