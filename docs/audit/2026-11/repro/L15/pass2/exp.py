"""L15 perturbation experiment: generate a sim dataset with a perturbed ai_agent profile, replay with mock LLM.

Usage: PYTHONPATH=$MYDIR/src python exp.py <variant> <seed> <outdir>
Patches are applied in-process (monkeypatch); repository files are not touched.
"""

from __future__ import annotations

import asyncio
import json
import random
import sys
from pathlib import Path

from tokiwa.eval import profiles as PR
from tokiwa.eval import sim as SIM
from tokiwa.eval.dataset import generate_events, write_dataset
from tokiwa.eval.harness import ReplayOptions
from tokiwa.eval.report import run_evaluation

MIX = {"ai_agent": 4, "benign_browser": 8, "human_attacker": 3, "scanner": 2, "llm_app_attacker": 2}

variant, seed, out = sys.argv[1], int(sys.argv[2]), Path(sys.argv[3])
parts = set(variant.split("+"))
canary = "nocanary" not in parts

if "canary_p30" in parts:  # agent notices/obeys the hidden instruction only 30% of the time
    _orig = PR.find_canary_instructions
    _r = random.Random(seed * 7919)

    def _fc(body):  # type: ignore[no-untyped-def]
        found = _orig(body)
        return found if (found and _r.random() < 0.3) else []

    PR.find_canary_instructions = _fc

if "browserua" in parts:  # agent drives a real browser / sets a Chrome UA (header set follows family)
    PR.PROFILES["ai_agent"] = PR.Profile(
        "ai_agent", "ai_agent", "x", PR.ai_agent, lambda rng, ip: PR.ClientIdentity(
            source_ip=ip, user_agent=PR._CHROME[0], family="chrome", accept_language="en-US,en;q=0.9")
    )

if "requestsua" in parts:  # same agent, python-requests instead of httpx/aiohttp/Go
    PR.PROFILES["ai_agent"] = PR.Profile(
        "ai_agent", "ai_agent", "x", PR.ai_agent,
        lambda rng, ip: PR.ClientIdentity(source_ip=ip, user_agent="python-requests/2.32.3", family="requests"),
    )

if "slow" in parts:  # slower / rate-limited model: median think 20 s, heavier tail
    def _tg(rng):  # type: ignore[no-untyped-def]
        if rng.random() < 0.08:
            return rng.uniform(60.0, 240.0)
        return PR.lognormal(rng, 20.0, 0.9, 3.0, 180.0)

    PR.think_gap = _tg

if "x2" in parts:  # mild: think gaps x2 only (same shape)
    _otg = PR.think_gap
    PR.think_gap = lambda rng: 2.0 * _otg(rng)

if "nonl" in parts:  # no sim-specific natural-language vocabulary shared with aidetect/payloads.py
    from tokiwa.eval import payloads as PL
    PL.NL_COMMENTS[:] = ["-- -"]
    PL.NL_PROBE_VALUES[:] = ["admin123", "Passw0rd!", "letmein", "password"]

if "freshmut" in parts:  # after an error the agent picks another known payload instead of editing the last one
    from tokiwa.eval import payloads as PL
    import os.path as _op

    def _fresh(p, step, rng):  # type: ignore[no-untyped-def]
        fam = max(PL.FAMILIES.values(), key=lambda lst: max(len(_op.commonprefix([p, x])) for x in lst))
        return rng.choice([x for x in fam if x != p] or fam)

    PL.mutate = _fresh

if "serial" in parts:  # one tool call per LLM turn: no parallel fan-out
    _ob = SIM.SessionContext.burst

    async def _burst(self, specs, *, spacing_ms=(2.0, 25.0)):  # type: ignore[no-untyped-def]
        if self.labels.get("profile") != "ai_agent":
            return await _ob(self, specs, spacing_ms=spacing_ms)
        res = []
        for i, s in enumerate(specs):
            if i:
                await self.sleep(PR.lognormal(self.rng, 3.0, 0.5, 1.0, 15.0))
            res.append((await _ob(self, [s], spacing_ms=spacing_ms))[0])
        return res

    SIM.SessionContext.burst = _burst


async def main() -> None:
    out.mkdir(parents=True, exist_ok=True)
    ds = out / "ds.jsonl"
    events = await generate_events(MIX, seed=seed, canary=canary)
    write_dataset(ds, events, {"variant": variant, "seed": seed})
    doc = await run_evaluation(ds, out / "run", ReplayOptions(llm="mock"))
    m = doc["metrics"]
    ai = m["ai_attribution"]
    ai_sess = [s for s in ai["sessions"] if s["actor"] == "ai_agent"]
    summ = {
        "variant": variant,
        "seed": seed,
        "events": len(events),
        "attack_session_rate": m["detection"]["attack_session_rate"],
        "benign_fpr": m["detection"]["benign_session_fpr"],
        "benign_fpr_med": m["detection"]["benign_session_fpr_medium_plus"],
        "alert_precision": m["alerts"]["precision"],
        "ai_P": ai["precision"], "ai_R": ai["recall"], "ai_F1": ai["f1"], "ai_AUC": ai["auc"],
        "ai_tp": ai["tp"], "ai_fp": ai["fp"], "ai_fn": ai["fn"],
        "ai_beh": [s["behaviour"] for s in ai_sess],
        "ai_comb": [s["combined"] for s in ai_sess],
        "ai_conf": ai["confusion"].get("ai_agent"),
        "ai_profile_det": m["per_profile"].get("ai_agent", {}).get("detection_rate"),
        "canary_follow_events": sum(
            1 for e in events if (e.labels or {}).get("attack") == "ai_canary_follow"),
        "ai_rules": sorted({r["rule_id"] for r in m["per_detector"] if r["rule_id"].startswith("ai.")}),
        "deception_alerts": sum(r["alerts"] for r in m["per_detector"] if r["rule_id"].startswith("deception")),
    }
    (out / "summary.json").write_text(json.dumps(summ))
    print(json.dumps(summ))


asyncio.run(main())
