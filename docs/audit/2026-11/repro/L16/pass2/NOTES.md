# L16 benign FP — pass2 notes
- approach: corpus.py builds benign Events per scenario (1 IP per scenario), run.py replays via tokiwa.eval.harness.replay (full pipeline, mock LLM; mock triage = rule fallback => HIGH->rate_limit, CRITICAL->block_ip, AI+HIGH->deceive)
- tuning mechanisms found: only detection.disabled_detectors / runtime overrides (global per detector). No per-path/IP/param suppression (grep suppress/allowlist: none). web_xss.py docstring mentions "suppression rule" that does not exist.
- engine.py:98 dedup excludes FALSE_POSITIVE status -> marking FP makes next hit a NEW alert (to verify)
## status
- [ ] corpus + replay  [ ] FP-mark test  [ ] Gate confirm
## done (resume)
- L16-01 no suppression (likely), L16-02 FP-mark -> new alert (confirmed via Gate), L16-03 benign text -> critical incident + block_ip (corpus + Gate)
- run1: 6855 events -> 42 alerts (crit4/high19/med17/low2), 3 incidents, 5 proposals, 82 mock LLM calls. Only text_user, authorised scan, k6 fired. SPA/machine/crawlers/deploy 5xx/404: 0 alerts.
- servers running: srv/server.pid victim.pid gate.pid(1979)
## next: L16-04 ai.natural_language_payload human->AI deceive; authorised scan (no allowlist) ; k6 flood; stop processes
- L16-04, L16-05 written
- all processes stopped (1331,1333,1341,1980)
- advisor fixes applied (L16-01 confirmed via tune.py, L16-02 low, L16-03 clean recount, L16-04 related). DONE.
