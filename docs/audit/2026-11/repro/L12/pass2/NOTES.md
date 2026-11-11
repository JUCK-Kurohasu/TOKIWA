# L12 pass2 notes
Done: read sensors/*, intel/_common, rss, matcher. Filed L12-04 (matcher version suffix FN).
Checked, not findings: RSS javascript: link stored but UI uses isSafeHttpUrl (safe); feedparser ignores XXE/billion laughs (t_rss.py).
In progress: Caddy >1MiB line -> truncated -> JSON fail -> dropped; host sensor max_connections truncation marks dropped as seen; agent restart gap (no offset persistence, start_at=end).
Next: nvd/osv/ghsa/jvn parsers (jvn XML), kev/epss.
- Filed L12-05 (host conn cap -> seen), L12-06 (no offset/spool persistence). Caddy long line: NOT a finding (complete lines <4MiB read whole).
- Filed L12-07 (suricata to_client attribution). Next: nginx escape silent drop, naive tz, withdrawn advisories.
- Filed L12-08 (format pitfalls), L12-09 (withdrawn). Next: cleanup PG from pass1, handback.
- Cleanup: pass1 PG not running; /tmp/l12pg removed. No processes started in pass2. DONE.
