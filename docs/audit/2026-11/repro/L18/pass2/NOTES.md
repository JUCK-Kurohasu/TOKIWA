# L18 pass2 notes
Ports 22800-22849. Findings -> findings/L18-day2ops.jsonl
## Plan
1 upgrade onto old schema (copy src + column)  2 live sqlite backup  3 secret.key lost/empty/rotated
4 misspelled settings / TOKIWA_CONFIG missing   5 last admin race  6 kill -9 during ingest
## Leads
- secret_key(): empty secret.key file -> "" key? (auth/security.py:44-60)
- TOKIWA_CONFIG nonexistent -> silently {} (config.py:354)
- extra=ignore everywhere -> misspelled protected_cidrs etc silently default
- delete_user last-admin check is count-then-delete (race)
## Done
