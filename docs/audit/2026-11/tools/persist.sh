#!/usr/bin/env bash
# Copy findings + issue map + repro scripts into the repo branch, commit and push. Usage: persist.sh "<commit subject>"
set -euo pipefail
A="$(cd "$(dirname "$0")" && pwd)"; R=/home/user/TOKIWA; D=$R/docs/audit/2026-11
cd "$R"; git checkout -q claude/affectionate-knuth-1inglo
mkdir -p "$D/findings" "$D/repro"; cp "$A"/findings/*.jsonl "$D/findings/"; [ -f "$A/issues/filed.json" ] && cp "$A/issues/filed.json" "$D/issues-filed.json"
mkdir -p "$D/tools"; for f in consolidate.py render2.py file_issues.py epic.py epic_head.md merge.json PASS2.md persist.sh; do [ -f "$A/$f" ] && sed "s#$A#\$AUDIT_DIR#g" "$A/$f" > "$D/tools/$f"; done
python3 - "$A" "$D" <<'PY'
import os, re, sys
A, D = sys.argv[1], sys.argv[2]
EXT = {".py", ".js", ".mjs", ".sh", ".md", ".txt", ".out", ".json", ".jsonl", ".csv", ".tsv", ".yaml", ".yml", ".http"}
SKIPDIR = {"venv", ".venv", "node_modules", "pylib", "data", "repo", "__pycache__", "src", "fe", "site-packages", ".git", "pgdata", "frontend"}
BADNAME = re.compile(r"token|secret|passw|\.pw$|\.key$|jwt|cookie|\.db|\.log$|\.pid$|admin|poc_redact", re.I)
SECRET = [(re.compile(r"tkw_[A-Za-z0-9_\-]{16,}"), "tkw_REDACTED"), (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"), "JWT_REDACTED"),
          (re.compile(r"sk-ant-[A-Za-z0-9_\-]{10,}"), "SK_REDACTED"), (re.compile(r'((?:password|passwd|pw)"?\s*[:=]\s*")([A-Za-z0-9_\-]{16,})(")'), r"\1PASSWORD_REDACTED\3")]
DROP = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}\b|ghp_[A-Za-z0-9]{20,}|xox[bp]-")
n = 0
for lane in sorted(os.listdir(os.path.join(A, "agents"))):
    for root, dirs, files in os.walk(os.path.join(A, "agents", lane)):
        dirs[:] = [d for d in dirs if d not in SKIPDIR and not d.startswith(("run", "eval", "."))]
        for f in files:
            p = os.path.join(root, f)
            if os.path.splitext(f)[1] not in EXT or BADNAME.search(f) or os.path.getsize(p) > 60_000 or os.path.islink(p): continue
            try: t = open(p, encoding="utf-8").read()
            except Exception: continue
            if DROP.search(t): continue
            for rx, rep in SECRET: t = rx.sub(rep, t)
            t = t.replace(A + "/agents/", "docs/audit/2026-11/repro/").replace(A, "$AUDIT_DIR")
            dst = os.path.join(D, "repro", os.path.relpath(p, os.path.join(A, "agents")))
            os.makedirs(os.path.dirname(dst), exist_ok=True); open(dst, "w", encoding="utf-8").write(t); n += 1
print("repro files:", n)
PY
# alg=none JWT test vectors (header eyJhbGciOiJub25l...) are detection payloads, not secrets.
if grep -rIhoE --exclude-dir=tools "tkw_[A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.|BEGIN [A-Z ]*PRIVATE KEY|sk-ant-" "$D" | grep -v "^eyJhbGciOiJub25l" | head -3 | grep -q .; then echo "SECRET-LIKE CONTENT FOUND, not committing"; exit 1; fi
git add docs/audit HANDOFF.md; if git diff --cached --quiet; then echo "nothing to commit"; exit 0; fi
git commit -q -m "$1

Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01YYAmEszC6ELXAVLnXjh6Hr"
for i in 1 2 3 4; do git push -q origin claude/affectionate-knuth-1inglo 2>&1 | grep -v "^remote:" | tail -2 && break; sleep $((2**i)); done
git log --oneline -1
