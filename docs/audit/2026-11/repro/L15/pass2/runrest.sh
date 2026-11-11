#!/bin/bash
cd /home/user/TOKIWA/backend
export TOKIWA_LLM__PROVIDER=mock PYTHONPATH=docs/audit/2026-11/repro/L15/pass2/src
run(){ /home/user/TOKIWA/backend/.venv/bin/python docs/audit/2026-11/repro/L15/pass2/exp.py $1 $2 docs/audit/2026-11/repro/L15/pass2/x/${1}_$2 2>>docs/audit/2026-11/repro/L15/pass2/x.err | tail -1 >> docs/audit/2026-11/repro/L15/pass2/results.jsonl; }
run nocanary+slow 5
for v in nocanary+serial nocanary+browserua nocanary+serial+slow nocanary+serial+slow+browserua; do for s in 1 2 3 4 5; do run $v $s; done; done
echo DONE >> docs/audit/2026-11/repro/L15/pass2/results.jsonl
