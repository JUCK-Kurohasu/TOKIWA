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


def _write_traffic(path: Path, exchanges: list[dict[str, object]]) -> Path:
    path.write_text(json.dumps({"version": 1, "exchanges": exchanges}))
    return path


def test_timing_label_and_seq_wrap_within_a_second(tmp_path: Path) -> None:
    """#72: ids are <unix>-<counter % 10000>; a second holding 9998, 9999, 0000, 0001 wrapped (small ones later)."""
    ids = ["1700000000-0001", "1700000000-9998", "1700000000-0000", "1700000000-9999"]
    path = _write_traffic(tmp_path / "t.json", [_exchange(i, 1700000000) for i in ids])
    events = import_artex(path)
    assert [e.labels["artex_id"] for e in events] == [
        "1700000000-9998",
        "1700000000-9999",
        "1700000000-0000",
        "1700000000-0001",
    ]
    assert all(e.labels["timing"] == "approx" for e in events)


def test_since_until_and_gap_split(tmp_path: Path) -> None:
    """#83: archives are per host, so two tasks an hour apart must be separable."""
    t0 = 1700000000
    times = [t0, t0 + 5, t0 + 20, t0 + 3600, t0 + 3610]
    path = _write_traffic(tmp_path / "t.json", [_exchange(f"{t}-{n:04d}", t) for n, t in enumerate(times)])

    one = import_artex(path)
    assert {e.labels["session"] for e in one} == {"artex:gate"}

    split = import_artex(path, split_gap_seconds=1800)
    sessions = {e.labels["session"]: e.source_ip for e in split}
    assert sessions == {"artex:gate#1": "198.51.100.200", "artex:gate#2": "198.51.100.201"}
    assert [e.labels["session"] for e in split] == ["artex:gate#1"] * 3 + ["artex:gate#2"] * 2

    assert len(import_artex(path, since=t0 + 3000)) == 2
    assert len(import_artex(path, since=t0, until=t0 + 20)) == 3


def test_parse_time_bound() -> None:
    from tokiwa.eval.artex import parse_time_bound

    assert parse_time_bound("1700000000") == 1700000000.0
    assert parse_time_bound("2023-11-14T22:13:20Z") == 1700000000.0
    assert parse_time_bound("2023-11-15T07:13:20+09:00") == 1700000000.0
    assert parse_time_bound("2023-11-14T22:13:20") == 1700000000.0  # no offset -> UTC


def test_cli_import_options_and_empty_hints(tmp_path: Path) -> None:
    """#26 / #83: an empty import says why (recording OFF vs. host filter vs. time window)."""
    runner = CliRunner()
    t0 = 1700000000
    traffic = _write_traffic(
        tmp_path / "t.json", [_exchange(f"{t}-0001", t) for t in (t0, t0 + 10, t0 + 4000)]
    )
    out = tmp_path / "a.jsonl"
    r = runner.invoke(
        eval_app, ["import-artex", str(traffic), "--out", str(out), "--split-gap-minutes", "30"]
    )
    assert r.exit_code == 0, r.output
    assert "2 session(s)" in r.output and "artex:gate#2: 1" in r.output
    meta = json.loads((tmp_path / "a.meta.json").read_text())
    assert meta["split_gap_minutes"] == 30 and meta["timing"].startswith("approx")

    empty = _write_traffic(tmp_path / "empty.json", [])
    r = runner.invoke(eval_app, ["import-artex", str(empty), "--out", str(tmp_path / "e.jsonl")])
    assert r.exit_code == 1 and "traffic_capture" in r.output

    r = runner.invoke(eval_app, ["import-artex", str(traffic), "--out", str(out), "--host", "victim"])
    assert r.exit_code == 1 and "gate (3)" in r.output and "traffic_capture" not in r.output

    r = runner.invoke(
        eval_app, ["import-artex", str(traffic), "--out", str(out), "--since", "2030-01-01T00:00:00Z"]
    )
    assert r.exit_code == 1 and "--since/--until" in r.output and "2023-11-14T22:13:20" in r.output
