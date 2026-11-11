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
