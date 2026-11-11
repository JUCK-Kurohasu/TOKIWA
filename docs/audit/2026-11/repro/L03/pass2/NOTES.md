# L03 pass2 NOTES
Ports: server 21300, victim 21301, gate 21302, sideapp 21303
Done: read rules, dedupe list. Existing L03-01..05 cover trip variants (redact, exact match), browser reach, static snippet, decoy fidelity.
In progress: lab start; (d) research; (a) API-only surfaces; (c) injection side effects (buffering, ETag, compression)
- Written L03-06 (inject buffering/compression), L03-07 (sjis), L03-08 (API surfaces + robots shadow)
- Next: (d) research -> L03-09 lure type; trip->block false attribution; honeytoken out-of-band (e)
- Written L03-09 (lure type/research), L03-10 (trip -> critical/ai_agent false attribution). Next: L03-11 honeytoken OOB/kill-chain
- Written L03-11 (honeytoken OOB / kill chain). Next: (b) residual: body formats/methods quick test; cleanup
- (b) residual test scripts/btest.py -> btest.out: form/multipart/PUT/OPTIONS/other header name/%5F-encoded path & query all trip.
  Not tripping: canary after 5KB of JSON (L05-02 truncation root cause, not filed) and JSON \uXXXX-escaped value (minor, not filed).
- All processes stopped (server/victim/gate/side/gate2). DONE. Findings L03-06..L03-11.
- L03-10 upgraded to high/confirmed: cross-site <img> GET -> critical incident + block_ip proposal for 198.51.100.7. Processes 12621/12622/12675 killed.
