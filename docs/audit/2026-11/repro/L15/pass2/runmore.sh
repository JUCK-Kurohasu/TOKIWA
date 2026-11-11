#!/bin/bash
while kill -0 846 2>/dev/null; do python3 -c 'import time;time.sleep(5)'; done
cd /home/user/TOKIWA/backend
export TOKIWA_LLM__PROVIDER=mock PYTHONPATH=docs/audit/2026-11/repro/L15/pass2/src
run(){ /home/user/TOKIWA/backend/.venv/bin/python docs/audit/2026-11/repro/L15/pass2/exp.py $1 $2 docs/audit/2026-11/repro/L15/pass2/x/${1}_$2 2>>docs/audit/2026-11/repro/L15/pass2/x.err | tail -1 >> docs/audit/2026-11/repro/L15/pass2/results2.jsonl; }
for v in nocanary+nonl nocanary+freshmut nocanary+nonl+freshmut nocanary+serial+slow+browserua+nonl+freshmut; do for s in 1 2 3 4 5; do run $v $s; done; done
echo DONE >> docs/audit/2026-11/repro/L15/pass2/results2.jsonl
