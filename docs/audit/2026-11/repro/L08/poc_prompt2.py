import sys
sys.argv=[sys.argv[0], sys.argv[1]]
exec(open(sys.argv[1]+"/poc_prompt.py").read().split("events = [")[0])  # reuse helpers/INJ
from tokiwa.triage.prompts import build_user_prompt
subject = TriageSubject(kind="alert", id="al1", title="SQL injection attempt", severity=Severity.HIGH, category="sqli", rule_ids=["web.sqli"], source_ips=["203.0.113.10"])
import re
def blk(u, name):
    s = u.find(f'name="{name}"'); e = u.find("</untrusted_data>", s); return u[s:e if e>0 else len(u)]
# Variant A: long header NAMES (~500 chars x 30 = 15k, under typical 16KiB header limits) -> evidence starvation
def evA(i):
    e = ev(i, "203.0.113.10", f"/api/items/{i}?id=1%27%20UNION%20SELECT%20password%20FROM%20users--", "python-httpx/0.27")
    e.http.header_order = ["x-pad-"+("a"*494)+f"{k:02d}" for k in range(30)]; e.http.headers={"user-agent":"python-httpx/0.27"}; e.http.query=None
    return e
evs = [evA(i) for i in range(25)]
ctx = TriageContext(evidence_ids=[e.id for e in evs], events=evs)
u = build_user_prompt(subject, ctx); b = blk(u, "evidence_events")
print("[A] evidence events fully/partly visible:", len(re.findall(r'"id": "ev\d+"', b)), "of 25; payload path visible:", b.count("UNION"))
# Variant B: '<'-heavy fields -> escape inflation after max_chars truncation, then gateway cap
def evB(i):
    e = ev(i, "203.0.113.10", "/"+"<"*2000, "UA"+"<"*2000); e.http.header_order=["x-a"]; return e
evs = [evB(i) for i in range(25)]
ctx = TriageContext(evidence_ids=[e.id for e in evs], events=evs, sessions=[{"id":"s1","features":{"note":"sessions block"}}])
u = build_user_prompt(subject, ctx); capped = LLMGateway(provider=MockProvider())._cap_input(u)
print("[B] evidence block chars after escape:", len(blk(u,'evidence_events')), "(max_chars=40000) user:", len(u), "capped:", len(capped))
print("[B] closing tags kept:", capped.count("</untrusted_data>"), "of", u.count("</untrusted_data>"), "| sessions block kept:", 'name="sessions"' in capped, "| retry note kept:", "IMPORTANT: your previous" in LLMGateway(provider=MockProvider())._cap_input(u+"\n\n"+RETRY_NOTE))
print("[B] tail:", repr(capped[-90:]))
