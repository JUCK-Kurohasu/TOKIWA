"""ARTEX traffic importer (synthetic fixtures in the documented formats) and the sim/eval CLIs."""

from __future__ import annotations

import base64
import json
import sqlite3
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from tokiwa.config import Settings
from tokiwa.eval.artex import import_artex
from tokiwa.eval.cli import app as eval_app
from tokiwa.eval.dataset import read_dataset
from tokiwa.eval.sim_cli import app as sim_app

REQ_HEAD = "POST /api/login?debug=1&token=abcdef123456 HTTP/1.1\nHost: gate:8080\nUser-Agent: python-httpx/0.28.1\nAuthorization: Bearer secretsecretsecret\nContent-Type: application/json\n"
RESP_HEAD = "HTTP 500\nContent-Type: application/json\n"
BODY = b'{"username": "admin\'--", "password": "hunter2hunter2"}'


def _exchange(ex_id: str, ts: int) -> dict[str, object]:
    return {
        "id": ex_id,
        "ts": ts,
        "host": "gate",
        "method": "POST",
        "url": "http://gate:8080/api/login?debug=1&token=abcdef123456",
        "status": 500,
        "content_type": "application/json",
        "req_len": len(BODY),
        "resp_len": 80,
        "req_head": REQ_HEAD,
        "req_body": base64.b64encode(BODY).decode(),
        "resp_head": RESP_HEAD,
    }


def _check(events: list) -> None:  # type: ignore[type-arg]
    assert events
    e = events[0]
    assert e.http.path == "/api/login" and e.http.method == "POST" and e.http.status == 500
    assert e.http.user_agent == "python-httpx/0.28.1"
    assert e.http.headers["authorization"].startswith("[REDACTED")
    assert "hunter2hunter2" not in (e.http.request_body or "") and "admin'--" in (e.http.request_body or "")
    assert "abcdef123456" not in (e.http.query or "")
    assert e.labels["actor"] == "ai_agent" and e.labels["session"] == "artex:gate"


def test_import_archive_snapshot_spreads_same_second(tmp_path: Path) -> None:
    doc = {
        "version": 1,
        "exchanges": [_exchange("1700000000-0002", 1700000000), _exchange("1700000000-0001", 1700000000)],
        "blobs": [],
    }
    path = tmp_path / "traffic" / "traffic.json"
    path.parent.mkdir()
    path.write_text(json.dumps(doc))
    events = import_artex(tmp_path)  # directory form (extracted task archive)
    _check(events)
    assert [e.labels["artex_id"] for e in events] == ["1700000000-0001", "1700000000-0002"]
    assert events[1].timestamp > events[0].timestamp
    assert import_artex(path, host="other") == []


def test_import_api_dump_zip_and_sqlite(tmp_path: Path) -> None:
    raw_req = REQ_HEAD + "\n" + BODY.decode()
    api = tmp_path / "dump.jsonl"
    api.write_text(json.dumps({"id": "1700000001-0001", "req": raw_req, "resp": RESP_HEAD + "\n{}"}) + "\n")
    _check(import_artex(api))

    zpath = tmp_path / "findings.zip"
    snap = {k: v for k, v in _exchange("x", 0).items() if k not in ("req_body", "ts", "id")}
    snap |= {"source_traffic_id": "1700000002-0001", "captured_at": 1700000002}
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("evidence/1/7/manifest.json", json.dumps({"role": "proof", "snapshot": snap}))
        zf.writestr("evidence/1/7/request.http", raw_req)
    _check(import_artex(zpath))

    db = tmp_path / "index.sqlite"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE exchanges (id TEXT, ts INTEGER, host TEXT, method TEXT, url_template TEXT, url TEXT, status INTEGER, content_type TEXT, req_len INTEGER, resp_len INTEGER, path TEXT)"
    )
    conn.execute(
        "CREATE TABLE exchange_bodies (id TEXT, req_head TEXT, req_body BLOB, req_blob TEXT, resp_head TEXT, resp_body BLOB, resp_blob TEXT)"
    )
    ex = _exchange("1700000003-0001", 1700000003)
    conn.execute(
        "INSERT INTO exchanges VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            ex["id"],
            ex["ts"],
            "gate",
            "POST",
            "/api/login",
            ex["url"],
            500,
            "application/json",
            len(BODY),
            80,
            "",
        ),
    )
    conn.execute(
        "INSERT INTO exchange_bodies VALUES (?,?,?,?,?,?,?)",
        (ex["id"], REQ_HEAD, BODY, None, RESP_HEAD, b"{}", None),
    )
    conn.commit()
    conn.close()
    _check(import_artex(db))


def test_cli_generate_eval_import_and_refusal(settings: Settings, tmp_path: Path) -> None:
    runner = CliRunner()
    ds = tmp_path / "ds.jsonl"
    r = runner.invoke(
        sim_app, ["generate", "--out", str(ds), "--profile", "ai_agent,benign_browser", "--seed", "4"]
    )
    assert r.exit_code == 0, r.output
    assert {e.labels["profile"] for e in read_dataset(ds)} == {"ai_agent", "benign_browser"}

    out = tmp_path / "run"
    r = runner.invoke(eval_app, ["run", "--dataset", str(ds), "--out", str(out)])
    assert r.exit_code == 0, r.output
    assert (out / "report.md").is_file()
    r = runner.invoke(eval_app, ["compare", str(out), str(out), "--fail-on-regression"])
    assert r.exit_code == 0 and "regressions: none" in r.output

    r = runner.invoke(eval_app, ["run", "--dataset", str(ds), "--llm", "live", "--out", str(tmp_path / "x")])
    assert r.exit_code == 2  # live requires an explicit --budget-usd

    r = runner.invoke(sim_app, ["run", "--profile", "scanner", "--target", "http://8.8.8.8"])
    assert r.exit_code == 2 and "refusing target" in r.output

    traffic = tmp_path / "traffic.json"
    traffic.write_text(json.dumps({"version": 1, "exchanges": [_exchange("1700000000-0001", 1700000000)]}))
    r = runner.invoke(eval_app, ["import-artex", str(traffic), "--out", str(tmp_path / "artex.jsonl")])
    assert r.exit_code == 0, r.output
    r = runner.invoke(eval_app, ["info", str(tmp_path / "artex.jsonl")])
    assert '"artex"' in r.output
