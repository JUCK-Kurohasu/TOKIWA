import json, sys, httpx
BASE, PATH = sys.argv[1], sys.argv[2]
cr = json.load(open(PATH))
c = httpx.Client(base_url=BASE, timeout=30)
pol = c.get("/api/v1/gate/policy", headers={"X-Tokiwa-Token": cr["tok-gate"]["token"]}).json()
assets = c.get("/api/v1/deception/assets", headers={"Authorization": "Bearer " + cr["admin"]["jwt"]}).json()
blob = json.dumps(pol, ensure_ascii=False)
print("decoy routes:", len(pol["decoys"]), "paths:", [d["path"] for d in pol["decoys"]])
print("html_injection present:", bool(pol.get("html_injection")), "len", len(pol.get("html_injection") or ""))
leaked = [(a["kind"], a["name"]) for a in assets if a.get("token") and a["token"] in blob]
print("assets:", len(assets), "asset tokens found verbatim in gate policy:", len(leaked), leaked)
# mask token values in any print: show only kinds
print("blocked:", pol["blocked"], "deceive:", pol["deceive"])
