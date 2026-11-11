#!/bin/bash
# usage: start_all.sh  (starts server 18250, victim 18251, gateA 18252 trust-off->victim, gateB 18253 trust-on->victim, rawup 18254, gateC 18255 trust-off->rawup)
source docs/audit/2026-11/repro/L06/env.sh
export TOKIWA_RESPONSE__PROTECTED_CIDRS='["10.255.255.0/24"]' TOKIWA_RESPONSE__PROTECT_SERVER_ADDRESSES=false
L=$MYDIR/logs; P=$MYDIR/pids; mkdir -p $P
start() { name=$1; shift; nohup "$@" > $L/$name.log 2>&1 & echo $! > $P/$name.pid; }
cd $B
[ "$1" != "nogate" ] && start server $B/.venv/bin/tokiwa serve --host 127.0.0.1 --port 18250
cd /home/user/TOKIWA/lab/victim; start victim $B/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 18251
cd $MYDIR; start rawup $B/.venv/bin/python $MYDIR/scripts/raw_upstream.py 18254 $L/rawup.jsonl
cd $B; sleep 6
G="$B/.venv/bin/tokiwa gate run --server http://127.0.0.1:18250 --token-file $D/gate.token --policy-refresh 1"
start gateA $G --upstream http://127.0.0.1:18251 --listen 127.0.0.1:18252 --sensor-id gateA
start gateB $G --upstream http://127.0.0.1:18251 --listen 127.0.0.1:18253 --sensor-id gateB --trust-forwarded-for
start gateC $G --upstream http://127.0.0.1:18254 --listen 127.0.0.1:18255 --sensor-id gateC
sleep 4; for f in $P/*.pid; do echo "$(basename $f .pid) $(cat $f) $(ps -p $(cat $f) -o comm= || echo DEAD)"; done
