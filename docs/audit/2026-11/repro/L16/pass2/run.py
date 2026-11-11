"""Replay the benign corpus through the real pipeline (mock LLM) and count outputs per scenario/rule/severity."""
from __future__ import annotations
import asyncio, json, logging, os, sqlite3, sys
from collections import Counter, defaultdict
from pathlib import Path

MY = Path(__file__).resolve().parent
sys.path.insert(0, str(MY))
os.environ.update({"TOKIWA_ENV": "test", "TOKIWA_CONFIG": str(MY / "none.yaml"), "TOKIWA_LLM__PROVIDER": "mock",
                   "TOKIWA_DETECTION__SIGMA_RULE_DIRS": '["/home/user/TOKIWA/rules/sigma"]'})
logging.disable(logging.WARNING)
from tokiwa.eval.harness import replay, ReplayOptions  # noqa
import corpus  # noqa

out = MY / (sys.argv[1] if len(sys.argv) > 1 else "run1")
events = corpus.build(1)
print("events in:", len(events), "scenarios:", Counter(corpus.SCEN.values()).most_common())
ev_scen = Counter(corpus.SCEN[e.source.ip] for e in events)
res = asyncio.run(replay(events, out, ReplayOptions(llm="mock")))
sc = lambda ip: corpus.SCEN.get(ip or "", "?")
by = defaultdict(Counter)
for a in res.alerts:
    by[sc(a.get("source_ip"))][(a["rule_id"], str(a["severity"]))] += 1
sev = Counter(str(a["severity"]) for a in res.alerts)
print("\nALERTS", len(res.alerts), dict(sev))
for s, c in sorted(by.items()):
    print(f"  {s} (events {ev_scen[s]}):", dict(c))
print("\nINCIDENTS", len(res.incidents))
for i in res.incidents:
    print("  ", str(i.get("severity")), i.get("title", "")[:90], "|", i.get("source_ips") if "source_ips" in i else "")
print("\nLLM calls", len(res.llm_calls), Counter(c.get("purpose") or c.get("task") for c in res.llm_calls))
db = sqlite3.connect(out / "eval.db")
rows = db.execute("select action_type,target,status,proposed_by from response_actions").fetchall()
print("\nPROPOSALS", len(rows))
for r in rows:
    print("  ", r, sc(r[1].split('/')[0]))
ai = [(sc(s.get("source_ip")), round(s.get("ai_score") or 0, 2)) for s in res.sessions if (s.get("ai_score") or 0) >= 0.5]
print("\nsessions ai>=0.5:", ai)
json.dump({"alerts": [{k: str(v) for k, v in a.items() if k in ("rule_id", "severity", "source_ip", "title", "count", "confidence")} | {"scen": sc(a.get("source_ip"))} for a in res.alerts]},
          open(out / "summary.json", "w"), ensure_ascii=False, indent=1)
