from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import uvicorn
from typer.testing import CliRunner

import tokiwa
from tokiwa import cli


@pytest.fixture
def uvicorn_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append({"app": app, **kw}))
    return calls


def test_serve_reload_watches_only_the_package_source(uvicorn_calls: list[dict[str, Any]]) -> None:
    # Watching the working directory (backend/) made watchfiles log every SQLite write under data/.
    result = CliRunner().invoke(cli.app, ["serve", "--reload"])
    assert result.exit_code == 0, result.output
    (call,) = uvicorn_calls
    assert call["reload"] is True
    assert call["reload_dirs"] == [str(Path(tokiwa.__file__).resolve().parent)]


def test_serve_without_reload_sets_no_watch_dirs(uvicorn_calls: list[dict[str, Any]]) -> None:
    result = CliRunner().invoke(cli.app, ["serve"])
    assert result.exit_code == 0, result.output
    (call,) = uvicorn_calls
    assert call["reload"] is False
    assert call.get("reload_dirs") is None
