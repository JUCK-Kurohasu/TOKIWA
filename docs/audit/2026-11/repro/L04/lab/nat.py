"""NAT: several benign clients (corporate NAT / carrier-grade NAT) share ONE source IP. Usage: nat.py <out> <seed>"""
import asyncio, json, sys
from dataclasses import replace
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import evasive; evasive.register()
from tokiwa.eval import sim, dataset
from tokiwa.eval.virtual import VirtualLab
from tokiwa.eval.report import run_evaluation
from tokiwa.eval.harness import ReplayOptions
async def main():
    root = Path(sys.argv[1]); root.mkdir(parents=True, exist_ok=True); seed = int(sys.argv[2])
    mix = {"fp_api_script": 2, "fp_mobile_app": 2, "fp_ci_contract_test": 1, "fp_sdk_poller": 1, "benign_browser": 4, "fp_browser_agent_headless": 1}
    plans = sim.build_plans(mix, seed=seed, spread_seconds=600)
    plans = [replace(p, identity=replace(p.identity, source_ip="198.51.100.77")) for p in plans]
    ex = await sim.simulate_offline(plans, start=dataset.DEFAULT_START, lab=VirtualLab(canary=True))
    ev = sim.exchanges_to_events(ex, seed=seed)
    ds = root / f"nat-s{seed}.jsonl"; dataset.write_dataset(ds, ev)
    doc = await run_evaluation(ds, root / f"run-nat-s{seed}", ReplayOptions(llm="mock"))
    ai = doc["metrics"]["ai_attribution"]
    for s in ai["sessions"]:
        print(json.dumps({k: s[k] for k in ("session", "predicted_ai", "behaviour", "alert", "combined")}))
    print(json.dumps({"fp": ai["fp"], "tn": ai["tn"], "confusion": ai["confusion"], "alerts_by_profile": {k: v["alerts"] for k, v in doc["metrics"]["per_profile"].items()}, "rules": {d["rule_id"]: d["alerts"] for d in doc["metrics"]["per_detector"]}}))
asyncio.run(main())
