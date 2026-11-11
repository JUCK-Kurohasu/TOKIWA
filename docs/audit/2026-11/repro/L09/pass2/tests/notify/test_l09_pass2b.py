from __future__ import annotations

import asyncio
import base64

CAPTURED: list[str] = []


async def _smtp(reader, writer):
    writer.write(b"220 fake ESMTP\r\n"); await writer.drain()
    in_data = False
    while True:
        line = await reader.readline()
        if not line:
            break
        s = line.decode(errors="replace").rstrip("\r\n")
        if in_data:
            if s == ".":
                in_data = False; writer.write(b"250 ok\r\n")
            await writer.drain(); continue
        CAPTURED.append(s)
        u = s.upper()
        if u.startswith("EHLO"):
            writer.write(b"250-fake\r\n250 AUTH PLAIN LOGIN\r\n")
        elif u.startswith("AUTH"):
            writer.write(b"235 ok\r\n")
        elif u.startswith("DATA"):
            in_data = True; writer.write(b"354 go\r\n")
        elif u.startswith("QUIT"):
            writer.write(b"221 bye\r\n"); await writer.drain(); break
        else:
            writer.write(b"250 ok\r\n")
        await writer.drain()
    writer.close()


def _auth_secret():
    for s in CAPTURED:
        if s.upper().startswith("AUTH PLAIN "):
            return base64.b64decode(s.split()[2]).split(b"\x00")[2].decode()
    return None


async def test_e2_smtp(client, admin_headers, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "SK_REDACTED")
    srv = await asyncio.start_server(_smtp, "127.0.0.1", 21902)
    try:
        cfg = {"host": "127.0.0.1", "port": 21902, "from_addr": "a@x.test", "to_addrs": ["b@x.test"],
               "username": "u", "password_env": "ANTHROPIC_API_KEY", "starttls": False}
        r = await client.post("/api/v1/notify/channels", headers=admin_headers,
                              json={"kind": "email", "name": "e", "config": cfg, "min_severity": "critical"})
        print("\nE2 create:", r.status_code, r.json().get("config"))
        cid = r.json()["id"]
        r = await client.post(f"/api/v1/notify/channels/{cid}/test", headers=admin_headers)
        print("E2 test:", r.status_code, r.json())
        print("E2 secret received by arbitrary SMTP host (env ANTHROPIC_API_KEY):", _auth_secret())
        # stored password + host change keeps the secret
        CAPTURED.clear()
        cfg2 = dict(cfg, password="PASSWORD_REDACTED", password_env=None); cfg2.pop("password_env")
        cfg2["host"] = "smtp.corp.example"
        r = await client.post("/api/v1/notify/channels", headers=admin_headers,
                              json={"kind": "email", "name": "e2", "config": cfg2, "min_severity": "critical"})
        cid2 = r.json()["id"]; masked = r.json()["config"]
        print("E2 masked read:", masked)
        masked["host"] = "127.0.0.1"
        r = await client.patch(f"/api/v1/notify/channels/{cid2}", headers=admin_headers, json={"config": masked})
        print("E2 patch host->127.0.0.1 with masked pw:", r.status_code)
        r = await client.post(f"/api/v1/notify/channels/{cid2}/test", headers=admin_headers)
        print("E2 test2:", r.json(), "secret at new host:", _auth_secret())
        # port oracle
        for port in (21949, 22):
            masked2 = dict(masked, port=port)
            await client.patch(f"/api/v1/notify/channels/{cid2}", headers=admin_headers, json={"config": masked2})
            r = await client.post(f"/api/v1/notify/channels/{cid2}/test", headers=admin_headers)
            print(f"E2 oracle 127.0.0.1:{port} ->", r.json().get("error"))
    finally:
        srv.close(); await srv.wait_closed()


async def test_e3_gate_truth(client, admin_headers):
    r = await client.post("/api/v1/response/actions", headers=admin_headers,
                          json={"action_type": "block_ip", "target": "198.51.100.23", "reason": "t"})
    aid = r.json()["id"]
    r = await client.post(f"/api/v1/response/actions/{aid}/approve", headers=admin_headers)
    j = r.json()
    print("\nE3 no Gate ever connected; status:", j["status"], "result:", j["result"], "expires_at:", j["expires_at"])
    r = await client.get("/api/v1/health", headers=admin_headers)
    print("E3 health:", r.status_code, str(r.json())[:300])
