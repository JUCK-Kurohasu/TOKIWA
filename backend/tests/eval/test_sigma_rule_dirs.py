"""#177: the Sigma rule directory must not depend on the CWD, and a missing one must be loud (log + eval metrics)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from tokiwa.config import Settings, default_sigma_rule_dirs, reset_settings_cache
from tokiwa.detect.sigma.loader import SigmaRuleStore
from tokiwa.eval.harness import ReplayOptions, replay
from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo

REPO_ROOT = Path(__file__).resolve().parents[3]


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# stub\n", encoding="utf-8")
    return path


def test_default_resolves_the_source_checkout_from_any_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)  # neither the repo root nor backend/
    (rule_dir,) = default_sigma_rule_dirs()
    assert rule_dir.is_absolute()
    assert rule_dir == REPO_ROOT / "rules" / "sigma"
    assert any(rule_dir.rglob("*.yml"))


def test_default_for_a_copied_source_tree(tmp_path: Path) -> None:
    """The audit reproduced #177 with the package copied out of the repo: the old fallback then found nothing."""
    pkg_file = _touch(tmp_path / "checkout" / "backend" / "src" / "tokiwa" / "config.py")
    (tmp_path / "checkout" / "rules" / "sigma").mkdir(parents=True)
    assert default_sigma_rule_dirs(pkg_file, prefix=tmp_path / "venv") == [
        (tmp_path / "checkout" / "rules" / "sigma").resolve()
    ]


def test_default_for_the_docker_layout(tmp_path: Path) -> None:
    """deploy/Dockerfile: non-editable venv in /app/.venv, rules copied to /app/rules/sigma."""
    app = tmp_path / "app"
    pkg_file = _touch(app / ".venv" / "lib" / "python3.12" / "site-packages" / "tokiwa" / "config.py")
    (app / "rules" / "sigma").mkdir(parents=True)
    assert default_sigma_rule_dirs(pkg_file, prefix=app / ".venv") == [(app / "rules" / "sigma").resolve()]


def test_default_when_nothing_exists_names_the_first_candidate(tmp_path: Path) -> None:
    pkg_file = _touch(tmp_path / "x" / "backend" / "src" / "tokiwa" / "config.py")
    (rule_dir,) = default_sigma_rule_dirs(pkg_file, prefix=tmp_path / "venv")
    assert rule_dir == (tmp_path / "x" / "rules" / "sigma").resolve()
    assert not rule_dir.exists()


def test_legacy_relative_setting_still_resolves_from_backend(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(REPO_ROOT / "backend")
    store = SigmaRuleStore(settings.model_copy(deep=True))
    store.settings.detection.sigma_rule_dirs = [Path("../rules/sigma")]
    assert store.rule_dirs() == [(REPO_ROOT / "rules" / "sigma").resolve()]
    assert store.missing_dirs == []


def test_missing_dir_is_an_error_once_and_exposed(
    settings: Settings, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store = SigmaRuleStore(settings.model_copy(deep=True))
    bogus = tmp_path / "no-such-rules"
    store.settings.detection.sigma_rule_dirs = [bogus]
    with caplog.at_level(logging.WARNING, logger="tokiwa.detect.sigma.loader"):
        store.reload_files()
        store.load_file_rules()  # startup calls rule_dirs() several times
    errors = [r for r in caplog.records if r.levelno == logging.ERROR and "not found" in r.getMessage()]
    assert len(errors) == 1
    assert store.missing_dirs == [str(bogus)]
    assert store.rules() == []


def _labelled(i: int) -> Event:
    return Event(
        kind=EventKind.HTTP,
        dataset="gate.http",
        source=Endpoint(ip="203.0.113.7"),
        http=HttpInfo(method="GET", host="lab", path=f"/p{i}", status=200, user_agent="curl/8.5.0"),
        labels={"actor": "human", "profile": "human_attacker", "session": "h-01", "attack": "recon"},
    )


async def test_eval_records_sigma_rules_loaded(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events = [_labelled(i) for i in range(2)]
    res = await replay(events, tmp_path / "ok", ReplayOptions())
    assert res.sigma_rules_loaded is not None and res.sigma_rules_loaded >= 20
    assert res.sigma_rule_dirs_missing == []
    assert not any("sigma" in n for n in res.notes)

    bogus = tmp_path / "nowhere"
    monkeypatch.setenv("TOKIWA_DETECTION__SIGMA_RULE_DIRS", f'["{bogus}"]')
    reset_settings_cache()
    res = await replay([_labelled(i) for i in range(2)], tmp_path / "bad", ReplayOptions())
    assert res.sigma_rules_loaded == 0
    assert res.sigma_rule_dirs_missing == [str(bogus)]
    assert any("0 Sigma file rules" in n for n in res.notes)
    assert any(str(bogus) in n for n in res.notes)
