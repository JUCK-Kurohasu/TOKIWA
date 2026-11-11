#!/bin/bash
source docs/audit/2026-11/repro/L06/env.sh
export TOKIWA_RESPONSE__PROTECTED_CIDRS='["10.255.255.0/24"]' TOKIWA_RESPONSE__PROTECT_SERVER_ADDRESSES=false
cd $B; nohup $B/.venv/bin/tokiwa serve --host 127.0.0.1 --port 18250 >> $MYDIR/logs/server.log 2>&1 & echo $! > $MYDIR/pids/server.pid
