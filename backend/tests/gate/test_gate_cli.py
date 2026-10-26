from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import uvicorn
from typer.testing import CliRunner

from tokiwa import cli
from tokiwa.config import GateSettings, Settings
from tokiwa.gate.cli import parse_listen, resolve_settings


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0.0.0.0:9000", ("0.0.0.0", 9000)),
        ("127.0.0.1", ("127.0.0.1", 8080)),
        (":9001", ("0.0.0.0", 9001)),
        ("9002", ("0.0.0.0", 9002)),
        ("[::]:9003", ("::", 9003)),
        ("[::1]", ("::1", 8080)),
        ("::1", ("::1", 8080)),
        ("", ("0.0.0.0", 8080)),
    ],
)
def test_parse_listen(value: str, expected: tuple[str, int]) -> None:
    assert parse_listen(value, "0.0.0.0", 8080) == expected


def test_resolve_settings_precedence(tmp_path: Path) -> None:
    token_file = tmp_path / "gate.token"
    token_file.write_text("tkw_from_file\n", encoding="utf-8")
    base = GateSettings(sensor_id="from-env")
    s = resolve_settings(base, upstream="http://app:3000", listen=":9000", token_file=token_file)
    assert s.upstream == "http://app:3000"
    assert (s.listen_host, s.listen_port) == ("0.0.0.0", 9000)
    assert s.ingest_token is not None and s.ingest_token.get_secret_value() == "tkw_from_file"
    assert s.sensor_id == "from-env"  # untouched when no flag given
    s2 = resolve_settings(base, token="tkw_flag", token_file=token_file, trust_forwarded_for=True)
    assert s2.ingest_token is not None and s2.ingest_token.get_secret_value() == "tkw_flag"
    assert s2.trust_forwarded_for is True
    assert base.trust_forwarded_for is False  # copy, not mutation


def test_gate_subcommand_is_registered() -> None:
    result = CliRunner().invoke(cli.app, ["gate", "run", "--help"], env={"COLUMNS": "200"})
    assert result.exit_code == 0, result.output
    for flag in ("--upstream", "--listen", "--server", "--token", "--trust-forwarded-for"):
        assert flag in result.output


def test_gate_run_starts_uvicorn(settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    def fake_run(app: Any, **kwargs: Any) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("TOKIWA_GATE__SENSOR_ID", "gate-env")
    from tokiwa.config import reset_settings_cache

    reset_settings_cache()
    token_file = tmp_path / "t"
    token_file.write_text("tkw_cli", encoding="utf-8")
    result = CliRunner().invoke(
        cli.app,
        [
            "gate",
            "run",
            "--upstream",
            "http://127.0.0.1:3000",
            "--listen",
            "127.0.0.1:18080",
            "--server",
            "http://127.0.0.1:8788",
            "--token-file",
            str(token_file),
            "--capture-body-bytes",
            "1024",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured["host"] == "127.0.0.1" and captured["port"] == 18080
    assert captured["proxy_headers"] is False
    assert captured["server_header"] is False and captured["date_header"] is False
    gate = captured["app"].state.gate
    assert gate.settings.sensor_id == "gate-env"  # env-backed GateSettings still apply
    assert gate.settings.capture_body_bytes == 1024
    assert gate.token == "tkw_cli"
    assert "tkw_cli" not in result.output  # never echo the token
