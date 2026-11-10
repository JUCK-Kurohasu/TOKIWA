import json,sys,collections
rows=collections.defaultdict(list)
for f in sys.argv[1:]:
    for l in open(f):
        r=json.loads(l)
        if 'error' not in r: rows[r['variant']].append(r)
print("variant | seeds | attack-sess detected | AI attributed | max beh ai_score (range) | max combined | benign max | AUC | ai.* alerts")
for v,rs in rows.items():
    n=sum(r['n'] for r in rs); det=sum(r['detected'] for r in rs); ai=sum(r['ai_pred'] for r in rs)
    beh=[b for r in rs for b in r['beh']]; comb=[max([x for x in (a,t,b) if x is not None]) for r in rs for a,t,b in zip(r['alert_ai'],r['triage'],r['beh'])]
    aucs=[r['auc'] for r in rs]; air=collections.Counter()
    for r in rs: air.update(r['ai_rules'])
    print(f"{v} | {len(rs)} | {det}/{n} | {ai}/{n} | {min(beh):.2f}-{max(beh):.2f} | {max(comb):.2f} | {max(r['ben_max'] or 0 for r in rs):.3f} | {','.join(str(round(a,2)) if a is not None else '-' for a in aucs)} | {sum(air.values())}")
