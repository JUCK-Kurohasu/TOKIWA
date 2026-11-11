# L10 pass2 NOTES
Server: tokiwa serve :22000 PID in run/server.pid (data run/data). Admin jwt run/admin.jwt, ingest token run/ingest.token.
## done
- sink grep: no dangerouslySetInnerHTML; SafeMarkdown (copilot only), SafeLink/isSafeHttpUrl (intel), mitre links fixed host. No CSV export. No sourcemaps in dist.
- L10-04 (medium, confirmed): SafeMarkdown `/\host` treated as internal -> same-tab nav to attacker (copilot_links.js)
- L10-05 (low, confirmed): bidi/zero-width chars rendered raw (shot_events.png)
## next
- intel/news/research text, decoy preview, notification previews, deception page, triage panel
- L10-06 (medium, confirmed): active block shown "Gate rejects 403" with zero gates
- negatives: no URL-param-triggered mutation except /copilot?incident= (creates conv only, no LLM call); incident/session/alert detail lists bounded server-side (MAX_DETAIL_*); mock chat echoes only user text
- candidate: mock/rule triage labelled "LLM 提案"/model claude-* in llm_calls while provider=mock
- L10-07 mock shown as claude-opus (low). L10-08 viewer can drain LLM budget via copilot (low, likely). L10-09 timezone (low).
- negatives: viewer role scan -> only copilot writable (server-side RBAC OK, no client-only checks); CORS strict allowlist (default localhost:5173), bearer auth so no CSRF; decoy preview shown as text; notify URLs masked server-side; triage panel text only; no CSV/JSON export; no sourcemaps; npm audit = L13-01.
- ResearchTab/NewsTab arbitrary-label links = same root as L08-09 (not refiled)
- server stopped
