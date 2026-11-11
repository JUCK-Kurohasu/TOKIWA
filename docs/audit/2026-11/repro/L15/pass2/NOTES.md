# L15 pass2 NOTES (eval validity)
- done: read RULES/PASS2, dedupe list, eval/{harness,metrics,profiles,sim,mock}. src copied to MYDIR/src (no repo edits).
- in progress: reproduce lab-mini baseline; perturbation experiment (exp.py) on 5 seeds.
- next: findings L15-01.. (circularity, canary dominance, metric validity, docs claims)
- filed L15-02 (stats/metric defs), L15-03 (mock LLM limits), L15-04 (sigma cwd). L15-01 reserved for circularity/insensitivity (waiting serial/browserua results).
- results.jsonl: base/nocanary/canary_p30/requestsua/x2/slow all R=1.0 AUC=1.0 over 5 seeds.
- filed L15-01 (circularity/saturation with measured table). results2.jsonl = nonl/freshmut ablations.
- next: label-quality check (benign realism, per-event labels for ai_agent recon), docs claims, final report.
- filed L15-05 (compare comparability).
- DONE: all bg runs stopped; final report sent.
