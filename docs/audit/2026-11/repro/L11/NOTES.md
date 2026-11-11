# L11 ops notes
Findings written: L11-01..06 (L11-02 upgraded to confirmed with 25-min backlog measurement).
Measurements: load_results.jsonl (throughput); run2/data/tokiwa.db (15k events: 8.7k fixed + 6.3k rotated).
DB (run2, after triage drained): llm_calls 105.7MB/10,656 rows (~10KB/row, request_redacted avg 8.2KB),
 events 26.7MB/15k (~1.8KB/event + indexes ~3MB), actor_sessions 25.9MB/6,308, alerts 19.7MB/4,707, incidents 7.5MB.
RSS: server 134MB -> 521MB after 8.7k plain events (run2); run1 398->835MB. Cause not isolated (in-process tracemalloc run
 timed out on bus.drain due to triage backlog) -> pending.
TODO: observability (health/metrics), restart durability, DB per 100k, offline eval rot vs fixed.
Done after resume: L11-04 throughput, L11-05 alert flood (+offline eval fixed 63/3/9 vs rot 268/99/80), L11-06 db locked->LLM audit/budget loss,
L11-07 self-observability, L11-08 DB growth/100k, L11-09 in-process state/restart/scaling. Not done: RSS root cause, SSE queue test, concurrent gate+agent lock test.
