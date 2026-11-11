# L05 webdetect notes
Done: L05-01..03 (gate redaction/truncation/cookie masking), L05-04 JSON/multipart silent limits, L05-05 multipart boundary confusion,
L05-06 custom headers not scanned, L05-07 normalization gaps (low), L05-08 API-attack class gaps (BOLA etc.), L05-09 dedup escalation.
Artifacts: matrix.md/json (class x technique), api_coverage.md, t_dedup.py, t_redos.py (detector regexes: max 13ms/8KiB, no ReDoS; sigma |re accepts (a+)+$ -> already L08-06).
Pending: sigma evaluator correctness + bundled FP rules, rate detectors low-and-slow/distributed, benign FP sample.
Done (resume): L05-10 rate detectors (t_rest.py), L05-11 sigma duplicates/severity (t_fpsev.py), L05-12 benign FP. Sigma evaluator semantics: 13/13 cases correct (no finding). Detector regex ReDoS: none (max 13ms per 8KiB).
