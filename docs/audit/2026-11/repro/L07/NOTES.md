# L07 notes (agent 2)
- server run2 port 18301 pid in run2/server.pid, creds run2/creds.json
- matrix (agent1) anomalies reviewed: only expected (role from DB OK; no-exp JWT accepted only with real secret; tok_revoked 200 was a commit race -> L07-04)
- L07-03 login (no ratelimit, timing enum, no auth audit, sync scrypt). L07-04 commit-after-response race. L07-05 ingest framing (confirmed end-to-end block). L07-06 no size limits.
- TODO: filters/sort/limit, mass assignment users, SPA traversal, docs/CORS/errors exposure
- DONE: L07-07 last-admin TOCTOU (0 admins), L07-08 exposure (docs/openapi/version, /api/* SPA 200; traversal safe; CORS ok), L07-09 offset overflow/IntegrityError 500, L07-10 setup unauth first-run/TOCTOU (likely). L07-05 amended (block proposal from mock LLM, needs-live-llm).
- Checked OK: copilot IDOR (404 for others), copilot tools read-only (read_only_session), LIKE escaping, role from DB, alg none/wrong secret rejected, SPA traversal.
- Info: JWT without exp accepted (needs secret); read-scope tokens unusable on user routes (401).
- Untested: 5000-event flood throughput / LLM cost per ingest (CPU shared; overlaps llm lane).
- Server 18301 killed (pids 619/609/608).
