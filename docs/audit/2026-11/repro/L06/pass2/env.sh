export M=docs/audit/2026-11/repro/L06/pass2 B=/home/user/TOKIWA/backend
export TOKIWA_SERVER__DATA_DIR=docs/audit/2026-11/repro/L06/pass2/data TOKIWA_DATABASE__URL=sqlite+aiosqlite:///docs/audit/2026-11/repro/L06/pass2/data/tokiwa.db TOKIWA_SERVER__STATIC_DIR=/home/user/TOKIWA/frontend/dist TOKIWA_LLM__PROVIDER=mock
export TOKIWA_RESPONSE__PROTECTED_CIDRS='["10.255.255.0/24"]' TOKIWA_RESPONSE__PROTECT_SERVER_ADDRESSES=false
