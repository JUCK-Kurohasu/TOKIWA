B=/home/user/TOKIWA/backend; PY=$B/.venv/bin/python
export TOKIWA_LLM__PROVIDER=mock TOKIWA_SERVER__STATIC_DIR=/home/user/TOKIWA/frontend/dist
setd(){ export TOKIWA_SERVER__DATA_DIR=$1 TOKIWA_DATABASE__URL=sqlite+aiosqlite:///$1/tokiwa.db; mkdir -p $1; }
