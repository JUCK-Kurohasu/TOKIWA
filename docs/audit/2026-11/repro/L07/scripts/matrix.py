"""Authz matrix: every OpenAPI route x principal. Mutations use nonexistent ids / invalid bodies ([]) so nothing changes."""
import json, re, sys, time
import httpx, jwt

BASE, CREDS, SECRET_FILE, OUT = sys.argv[1:5]
cr = json.load(open(CREDS))
secret = open(SECRET_FILE).read().strip()
c = httpx.Client(base_url=BASE, timeout=10)
spec = c.get("/api/openapi.json").json()

PUBLIC = {("GET", "/api/v1/auth/status"), ("POST", "/api/v1/auth/setup"), ("POST", "/api/v1/auth/login"), ("GET", "/api/v1/health")}
ADMIN_RE = [r"^/api/v1/(audit|tokens|users|notify)", r"^PUT /api/v1/llm/config$", r"^GET /api/v1/llm/calls/\{", r"^POST /api/v1/llm/test$", r"^POST /api/v1/system/jobs/"]
ANALYST_RE = [r"^(POST|PATCH|DELETE|PUT) /api/v1/(alerts|assets|deception|detectors|hosts|incidents|intel|response|rules)", r"^GET /api/v1/deception/preview/"]

def expected(m, p):
    k = f"{m} {p}"
    if (m, p) in PUBLIC: return "public"
    if p == "/api/v1/ingest/events": return "ingest"
    if p == "/api/v1/gate/policy": return "gate"
    if any(re.search(r, k) or re.search(r, p) and r.startswith("^/") for r in ADMIN_RE): return "admin"
    if any(re.search(r, k) for r in ANALYST_RE): return "analyst"
    return "user"

now = int(time.time())
def tok(payload, key=secret, alg="HS256", headers=None):
    return jwt.encode(payload, key, algorithm=alg, headers=headers)
def claims(uid, **kw):
    d = {"sub": uid, "name": "x", "role": "viewer", "iat": now, "exp": now + 3600, "typ": "access"}
    d.update(kw); return {k: v for k, v in d.items() if v is not None}
vid, aid = cr["viewer1"]["id"], cr["admin"]["id"]
none_tok = jwt.encode(claims(aid, role="admin"), None, algorithm="none") if True else ""
P = {
 "none": {},
 "viewer": {"Authorization": "Bearer " + cr["viewer1"]["jwt"]},
 "analyst": {"Authorization": "Bearer " + cr["analyst1"]["jwt"]},
 "admin": {"Authorization": "Bearer " + cr["admin"]["jwt"]},
 "tok_ingest": {"X-Tokiwa-Token": cr["tok-ingest"]["token"]},
 "tok_gate": {"X-Tokiwa-Token": cr["tok-gate"]["token"]},
 "tok_read": {"X-Tokiwa-Token": cr["tok-read"]["token"]},
 "tok_read_bearer": {"Authorization": "Bearer " + cr["tok-read"]["token"]},
 "tok_revoked": {"X-Tokiwa-Token": cr["tok-revoked"]["token"]},
 "jwt_alg_none_admin": {"Authorization": "Bearer " + none_tok},
 "jwt_wrong_secret_admin": {"Authorization": "Bearer " + tok(claims(aid, role="admin"), key="wrong-secret-wrong-secret-wrong-secret!!")},
 "jwt_expired_admin": {"Authorization": "Bearer " + tok(claims(aid, role="admin", iat=now - 7200, exp=now - 3600))},
 "jwt_no_exp_admin": {"Authorization": "Bearer " + tok(claims(aid, role="admin", exp=None))},
 "jwt_no_typ_admin": {"Authorization": "Bearer " + tok(claims(aid, role="admin", typ=None))},
 "jwt_no_sub": {"Authorization": "Bearer " + tok(claims(None, role="admin"))},
 "jwt_unknown_sub": {"Authorization": "Bearer " + tok(claims("00000000deadbeef", role="admin"))},
 "jwt_viewer_role_claim_admin": {"Authorization": "Bearer " + tok(claims(vid, role="admin"))},
 "jwt_hs512_admin": {"Authorization": "Bearer " + tok(claims(aid, role="admin"), alg="HS512")},
 "jwt_kid_injection": {"Authorization": "Bearer " + tok(claims(aid), headers={"kid": "../../../dev/null"})},
 "admin_jwt_in_query": "QUERY",
}
# lifecycle principals (state changed by lifecycle.py before this run; jwt captured before change)
for k in ("deluser", "demoteuser", "pwchange"):
    if k in cr: P[f"stale_{k}"] = {"Authorization": "Bearer " + cr[k].get("jwt_before", cr[k]["jwt"])}

rows = []
for path, ops in spec["paths"].items():
    for m in ops:
        M = m.upper(); exp = expected(M, path)
        url = re.sub(r"\{[^}]+\}", "zz-nonexistent", path)
        for pname, hdr in P.items():
            params = None
            if hdr == "QUERY":
                hdr, params = {}, {"access_token": cr["admin"]["jwt"]}
            kw = {"headers": hdr, "params": params}
            if M in ("POST", "PUT", "PATCH"): kw["json"] = []
            try:
                if path.endswith("/stream"):
                    with c.stream(M, url, timeout=3, **kw) as r:
                        st, ct = r.status_code, r.headers.get("content-type", "")
                else:
                    r = c.request(M, url, **kw); st, ct = r.status_code, r.headers.get("content-type", "")
            except httpx.ReadTimeout:
                st, ct = -1, "timeout"
            rows.append({"method": M, "path": path, "expected": exp, "principal": pname, "status": st, "ctype": ct.split(";")[0]})

def should_allow(exp, p):
    if exp == "public": return True
    if exp == "ingest": return p == "tok_ingest"
    if exp == "gate": return p == "tok_gate"
    lvl = {"user": 0, "analyst": 1, "admin": 2}[exp]
    have = {"viewer": 0, "analyst": 1, "admin": 2, "stale_demoteuser": 0}.get(p)
    if p == "admin_jwt_in_query": return path_is_stream
    return have is not None and have >= lvl

anom = []
for r in rows:
    path_is_stream = r["path"].endswith("/stream")
    allowed = r["status"] not in (401, 403)
    sa = should_allow(r["expected"], r["principal"])
    if allowed != sa:
        anom.append({**r, "should_allow": sa})
json.dump(rows, open(OUT + "/matrix.json", "w"))
with open(OUT + "/matrix.csv", "w") as f:
    pn = list(P)
    f.write("method,path,expected," + ",".join(pn) + "\n")
    from collections import defaultdict
    g = defaultdict(dict)
    for r in rows: g[(r["method"], r["path"], r["expected"])][r["principal"]] = r["status"]
    for (m, p, e), d in g.items(): f.write(f"{m},{p},{e}," + ",".join(str(d.get(x)) for x in pn) + "\n")
json.dump(anom, open(OUT + "/matrix_anomalies.json", "w"), indent=1)
print("rows", len(rows), "anomalies", len(anom))
from collections import Counter
print(Counter((a["principal"], a["should_allow"], a["status"]) for a in anom).most_common(40))
