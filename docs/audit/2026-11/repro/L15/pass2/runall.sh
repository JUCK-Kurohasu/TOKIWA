#!/bin/bash
cd /home/user/TOKIWA/backend
export TOKIWA_LLM__PROVIDER=mock PYTHONPATH=docs/audit/2026-11/repro/L15/pass2/src
for v in base nocanary canary_p30 nocanary+requestsua nocanary+x2 nocanary+slow nocanary+serial nocanary+browserua nocanary+serial+slow; do
 for s in 1 2 3 4 5; do
  /home/user/TOKIWA/backend/.venv/bin/python docs/audit/2026-11/repro/L15/pass2/exp.py $v $s docs/audit/2026-11/repro/L15/pass2/x/${v}_$s 2>>docs/audit/2026-11/repro/L15/pass2/x.err | tail -1 >> docs/audit/2026-11/repro/L15/pass2/results.jsonl
 done
done
echo DONE >> docs/audit/2026-11/repro/L15/pass2/results.jsonl
