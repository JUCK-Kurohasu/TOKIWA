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
- L18-01 naive restore / DB URL typo -> empty DB, setup reopen (confirmed)
- L18-02 extra=ignore, TOKIWA_CONFIG missing silently (confirmed)
- L18-03 schema upgrade -> login 500 (confirmed)
- L18-04 credential lifecycle (confirmed partly)
- L18-05 last-admin race (confirmed first try)
- L18-06 disk full -> ingest 500, health ok (confirmed, tmpfs)
- kill -9 during ingest: 4 rounds (seq + 4 threads), acked == stored, integrity ok -> NO finding (positive)
- secret.key loss -> covered by L11-03 / L13-03 (empty key) -> no new finding
- triage lost on crash -> covered by L11-02
## Next: settings hot-reload / UI settings precedence, deploy restart policies, logging rotation
- L18-07 DB overlay beats env (confirmed)
## Status: DONE (7 findings L18-01..07). All servers stopped, tmpfs unmounted.
Not tested: PostgreSQL backup/restore (no PG here; L14-10), real Gate token rotation (likely only), time jumps/NTP, log rotation for non-docker, SIGTERM graceful shutdown with pending bus tasks (covered by L11-02/L11-09).
Note: CLI `tokiwa user create` on existing name prints IntegrityError with SQL params (in L18-04).
