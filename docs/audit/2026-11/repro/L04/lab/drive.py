"""L04 driver: python drive.py <outroot> <seed> <variant>[,<variant>...] [benign_n]
Generates {variant:4, benign_browser:benign_n} offline, runs eval (mock LLM), prints compact per-variant summary JSON."""
import asyncio, json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import evasive; evasive.register()
from tokiwa.eval.dataset import generate_events, write_dataset
from tokiwa.eval.report import run_evaluation
from tokiwa.eval.harness import ReplayOptions

async def one(root, seed, variant, nb, n):
    mix = {variant: n}
    if nb: mix["benign_browser"] = nb
    ds = root / f"{variant}-s{seed}.jsonl"
    ev = await generate_events(mix, seed=seed)
    write_dataset(ds, ev)
    out = root / f"run-{variant}-s{seed}"
    t = time.time()
    doc = await run_evaluation(ds, out, ReplayOptions(llm="mock"))
    m = doc["metrics"]
    ai = m["ai_attribution"]
    sess = [s for s in ai["sessions"] if s["session"].startswith(variant)]
    ben = [s for s in ai["sessions"] if not s["session"].startswith(variant)]
    prof = m["per_profile"].get(variant, {})
    r = {"variant": variant, "seed": seed, "events": len(ev), "n": len(sess),
         "detected": prof.get("detected"), "det_medplus": prof.get("detected_medium_plus"), "alerts": prof.get("alerts"),
         "ai_pred": sum(s["predicted_ai"] for s in sess),
         "beh": [round(s["behaviour"] or 0, 3) for s in sess], "alert_ai": [s["alert"] for s in sess],
         "triage": [s["triage"] for s in sess], "conf": ai["confusion"], "ai_rules": {d["rule_id"]: d["alerts"] for d in m["per_detector"] if d["rule_id"].startswith(("ai.","deception.","canary"))}, "all_rules": sorted(d["rule_id"] for d in m["per_detector"] if d["tp"]),
         "ben_fp": sum(s["predicted_ai"] for s in ben), "ben_max": max([s["combined"] for s in ben], default=None),
         "precision": ai.get("precision"), "recall": ai.get("recall"), "auc": ai.get("auc"), "secs": round(time.time()-t, 1)}
    print(json.dumps(r, ensure_ascii=False), flush=True)
    return r

async def main():
    root = Path(sys.argv[1]); root.mkdir(parents=True, exist_ok=True)
    seed = int(sys.argv[2]); nb = int(sys.argv[4]) if len(sys.argv) > 4 else 4
    n = int(sys.argv[5]) if len(sys.argv) > 5 else 4
    for v in sys.argv[3].split(","):
        try:
            await one(root, seed, v, nb, n)
        except Exception as e:
            print(json.dumps({"variant": v, "error": repr(e)[:300]}), flush=True)
asyncio.run(main())
