# L16 benign FP — pass2 notes
- approach: corpus.py builds benign Events per scenario (1 IP per scenario), run.py replays via tokiwa.eval.harness.replay (full pipeline, mock LLM; mock triage = rule fallback => HIGH->rate_limit, CRITICAL->block_ip, AI+HIGH->deceive)
- tuning mechanisms found: only detection.disabled_detectors / runtime overrides (global per detector). No per-path/IP/param suppression (grep suppress/allowlist: none). web_xss.py docstring mentions "suppression rule" that does not exist.
- engine.py:98 dedup excludes FALSE_POSITIVE status -> marking FP makes next hit a NEW alert (to verify)
## status
- [ ] corpus + replay  [ ] FP-mark test  [ ] Gate confirm
