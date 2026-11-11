import sys, json
sys.path.insert(0, sys.argv[1])
from harness import *
J="application/json"
evs = [direct_event("/docs?file=guide/../intro.md"), direct_event("/settings?callback=http%3A%2F%2Flocalhost%3A3000%2Fcb"),
 direct_event("/kb?q=use%20%60ls%20-la%60%20%7C%20grep%20foo"),
 direct_event('/api/posts', method='POST', ct=J, body=json.dumps({"md": "Use `<script src=app.js></script>` in index.html"})),
 direct_event('/api/posts', method='POST', ct=J, body=json.dumps({"code": "import os\nos.system('ls')\nprint(open('/etc/hosts').read())"}))]
for ds in run_drafts(evs):
    print([(d.rule_id[:14], str(d.severity).split('.')[-1], round(d.confidence,2), (d.ai_score or 0), d.title[:55]) for d in ds])
