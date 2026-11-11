# L09 pass2 NOTES
Done: read respond/{service,validate,policy,executors,expiry}.py, notify/{outbound,channels,service,render}.py, routes, bus.py.
Known/skip: four-eyes not implemented (docs/response.md:185) -> skip.
Candidates (to confirm):
- E1 notify dedup race: should_send checked before send, mark after -> burst = N notifications; no global rate cap; unbounded tasks.
- E2 email channel: password_env reads ANY env var; SMTP host has no SSRF guard / allowed_hosts; starttls=false sends AUTH clear; merge_masked keeps password/headers when host changes; error type = port oracle.
- E3 Gate executor marks active without any gate ack (no gate heartbeat tracked).
- E4 Discord embed: markdown masked links not escaped (title/desc/reason attacker/LLM controlled).
- E5 auto-approved actions: action.proposed notification says "Nothing runs until a human approves" (race).
Ports: 21900-21949. PIDs in $M/*.pid
- L09-07 (dedup race) and L09-08 (discord md) written. E5 disproved (shows auto-approved). Next: E2 SMTP, E3 gate truth.
- L09-09 (SMTP password_env exfil, confirmed) and L09-10 (gate active w/o ack, confirmed) written. Next: approval races / auto-approve scope / CIDR+IPv6+TTL / expiry revert failure
## Status (final)
Written: L09-07 (notify dedup race/flood, confirmed), L09-08 (Discord markdown, likely), L09-09 (SMTP password_env exfil, confirmed),
L09-10 (gate active w/o ack, confirmed), L09-11 (TTL not extended / no recidivism, likely), L09-12 (approval record integrity, likely).
Checked & clean: approve/reject/revert/expire transitions are atomic conditional UPDATEs (no double-approve, approve-vs-expire race);
_execute refuses non-approved; startup marks interrupted approved rows failed. Auto-approve: two-key switch, applies to any proposer/type;
framing via auto-approve already covered by L09-01, L07-05, L06-01 -> not refiled. Four-eyes: documented as not implemented (docs/response.md:185).
TTL capped 7d (no permanent blocks); min_prefix 16/48. protected_cidrs default lacks 169.254/16, fe80::/10; protect_server_addresses
covers TOKIWA host only, not Gate host (mostly covered by L09-01). SSRF/DNS rebinding = L13-04. E5 hypothesis (auto-approved shown as pending) disproved.
Note: pass1 L09-03 'related' cites L09-08/L09-10 which now are different findings (pass1 ids were never written).
Not tested: Discord/Slack real rendering & 429 (no network), live-LLM reason steering, nftables (no nft/root), DNS rebinding.
Harness: tests/notify/test_l09_pass2.py, test_l09_pass2b.py (run from backend with repo venv, -c /dev/null). No processes left running.
