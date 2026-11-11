import time
from tokiwa.intel.advisor import validate_proposed_rule
from tokiwa.schemas.intel import ProposedRule
from tokiwa.detect.sigma.parser import parse_rule
rule = """title: LLM proposed rule
id: llm-redos-1
status: experimental
logsource: {category: webserver}
detection:
  sel:
    cs-uri-query|re: '^(a+)+$'
  condition: sel
level: medium
"""
pr = ProposedRule.model_validate({"kind":"sigma","title":"x","content":rule,"rationale":"r"}) if 'rationale' in ProposedRule.model_fields else ProposedRule(kind="sigma", content=rule, **{k:"x" for k,f in ProposedRule.model_fields.items() if f.is_required() and k not in("kind","content")})
print("validate_proposed_rule:", validate_proposed_rule(pr)[:2])
r = parse_rule(rule)
import re
rx = re.compile(r'^(a+)+$')
for n in (20, 22, 24):
    t=time.time(); rx.match("a"*n+"!"); print(f"n={n} match time {time.time()-t:.2f}s")
