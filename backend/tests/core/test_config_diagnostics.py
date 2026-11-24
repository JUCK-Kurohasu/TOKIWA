"""Audit #161: configuration mistakes are reported instead of silently falling back to the defaults."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from tokiwa.config import ConfigError, Settings, get_settings, reset_settings_cache
from tokiwa.config_diagnostics import (
    config_issues,
    display_value,
    effective_config,
    env_issues,
    file_issues,
    startup_summary,
)

REPO = Path(__file__).resolve().parents[3]
SECRET = "sk-ant-PLANTED-SECRET-VALUE-0123456789"


def _keys(issues: list) -> list[str]:  # type: ignore[type-arg]
    return [i.key for i in issues]


# ----------------------------------------------------------------------------------------------- environment
def test_env_typos_are_reported_with_hints_and_without_values() -> None:
    issues = env_issues(
        environ={
            "TOKIWA_LLM__PROVIDR": SECRET,
            "TOKIWA_RESPONSE__PROTECTED_CIDR": '["10.0.0.0/8"]',
            "TOKIWA_DATABASE__URI": "x",
            "TOKIWA_LLM_PROVIDER": "mock",  # one underscore instead of two
            "TOKIWA_LLMX__FOO": "1",
            "TOKIWA_SERVER__PORT__X": "1",  # scalar field cannot be nested into
            "OTHER_VAR": "ignored",
        }
    )
    by_key = {i.key: i for i in issues}
    assert set(by_key) == {
        "TOKIWA_LLM__PROVIDR",
        "TOKIWA_RESPONSE__PROTECTED_CIDR",
        "TOKIWA_DATABASE__URI",
        "TOKIWA_LLM_PROVIDER",
        "TOKIWA_LLMX__FOO",
        "TOKIWA_SERVER__PORT__X",
    }
    assert by_key["TOKIWA_LLM__PROVIDR"].hint == "did you mean TOKIWA_LLM__PROVIDER?"
    assert by_key["TOKIWA_RESPONSE__PROTECTED_CIDR"].hint == "did you mean TOKIWA_RESPONSE__PROTECTED_CIDRS?"
    assert by_key["TOKIWA_DATABASE__URI"].hint == "did you mean TOKIWA_DATABASE__URL?"
    assert "TOKIWA_LLM__PROVIDER" in (by_key["TOKIWA_LLM_PROVIDER"].hint or "")
    assert all(SECRET not in str(i) for i in issues)


def test_env_known_names_are_quiet() -> None:
    assert (
        env_issues(
            environ={
                "TOKIWA_ENV": "prod",
                "tokiwa_log_level": "DEBUG",  # case-insensitive like pydantic-settings
                "TOKIWA_LLM__REDACTION__ENABLED": "true",  # two levels of nesting
                "TOKIWA_LLM__PRICING__MY_MODEL": "{}",  # dict field: any sub-key
                "TOKIWA_LLM": "{}",  # whole section as JSON
                "TOKIWA_CONFIG": "/etc/tokiwa/tokiwa.yaml",
                "TOKIWA_STRICT_CONFIG": "1",
                "TOKIWA_HEALTHCHECK_URL": "none",
                "TOKIWA_NOTIFY_SMTP_RELAY1": "x",  # e-mail password variables (notify)
                "TOKIWA_SMTP_PASSWORD": "x",
            }
        )
        == []
    )


def test_configured_smtp_password_env_is_quiet(settings: Settings) -> None:
    s = settings.model_copy(
        update={"notify": settings.notify.model_copy(update={"smtp_password_envs": ["TOKIWA_MAIL_PW"]})}
    )
    assert env_issues(environ={"TOKIWA_MAIL_PW": "x"}) != []
    assert env_issues(s, environ={"TOKIWA_MAIL_PW": "x"}) == []


def _shipped_env_names() -> set[str]:
    """TOKIWA_* names that the shipped image / compose files / .env.example put into a container's environment."""
    names: set[str] = set()
    pattern = re.compile(r"\bTOKIWA_[A-Z0-9_]+")
    dockerfile = (REPO / "deploy" / "Dockerfile").read_text(encoding="utf-8")
    env_block = dockerfile[dockerfile.index("ENV PATH=") : dockerfile.index("USER ${TOKIWA_UID}")]
    names |= set(pattern.findall(env_block))
    # .env reaches the deploy containers (env_file), commented examples included: users uncomment them.
    for line in (REPO / ".env.example").read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s*#?\s*(TOKIWA_[A-Z0-9_]+)=", line)
        if m:
            names.add(m.group(1))
    for compose in ("deploy/compose.yaml", "lab/compose.yaml"):
        doc = yaml.safe_load((REPO / compose).read_text(encoding="utf-8"))
        for service in doc["services"].values():
            env = service.get("environment") or {}
            names |= {k for k in (env if isinstance(env, dict) else [e.split("=", 1)[0] for e in env])}
    # deploy/compose.yaml interpolations are read from the same .env file.
    names |= set(
        re.findall(r"\$\{(TOKIWA_[A-Z0-9_]+)", (REPO / "deploy/compose.yaml").read_text(encoding="utf-8"))
    )
    return {n for n in names if n.startswith("TOKIWA_")}


def test_shipped_deployment_variables_produce_no_warnings() -> None:
    names = _shipped_env_names()
    assert {"TOKIWA_ENV", "TOKIWA_GATE__UPSTREAM", "TOKIWA_BIND", "TOKIWA_HEALTHCHECK_URL"} <= names
    assert env_issues(environ=dict.fromkeys(names, "x")) == []


# ----------------------------------------------------------------------------------------------- config file
def test_yaml_unknown_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "tokiwa.yaml"
    cfg.write_text(
        "llm:\n  providr: mock\n  redaction:\n    enabld: true\n  pricing:\n    any-model: {input: 1}\n"
        "LLM: {}\nresponse:\n  protected_cidrs: ['10.0.0.0/8']\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("TOKIWA_CONFIG", str(cfg))
    issues = {i.key.removeprefix(f"{cfg}: "): i for i in file_issues()}
    assert set(issues) == {"llm.providr", "llm.redaction.enabld", "LLM"}
    assert issues["llm.providr"].hint == "did you mean llm.provider?"
    assert issues["llm.redaction.enabld"].hint == "did you mean llm.redaction.enabled?"
    assert issues["LLM"].hint == "keys are case-sensitive: llm"


@pytest.mark.parametrize("kind", ["missing", "directory"])
def test_explicit_config_file_missing_or_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    target = tmp_path / "tokiwa.yaml"
    if kind == "directory":
        target.mkdir()  # what Docker creates for a bind mount whose source file is missing
    monkeypatch.setenv("TOKIWA_CONFIG", str(target))
    (issue,) = file_issues()
    assert issue.key == str(target)
    assert ("directory" in issue.problem) is (kind == "directory")


@pytest.mark.parametrize("value", ["", os.devnull])
def test_empty_or_devnull_means_no_file(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("TOKIWA_CONFIG", value)
    assert file_issues() == []


def test_implicit_default_file_is_optional(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TOKIWA_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    assert file_issues() == []
    (tmp_path / "tokiwa.yaml").mkdir()
    assert "directory" in file_issues()[0].problem


# ----------------------------------------------------------------------------------------------- startup
def test_get_settings_warns_and_strict_refuses(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("TOKIWA_LLM__ANTHROPIC_API_KEYY", SECRET)
    reset_settings_cache()
    with caplog.at_level(logging.WARNING, logger="tokiwa.config"):
        get_settings()
    assert [r.getMessage() for r in caplog.records] == [
        "config: TOKIWA_LLM__ANTHROPIC_API_KEYY: 'anthropic_api_keyy' is not a field of llm: ignored "
        "(did you mean TOKIWA_LLM__ANTHROPIC_API_KEY?)"
    ]
    monkeypatch.setenv("TOKIWA_STRICT_CONFIG", "1")
    reset_settings_cache()
    with pytest.raises(ConfigError) as exc:
        get_settings()
    assert "TOKIWA_LLM__ANTHROPIC_API_KEYY" in str(exc.value) and SECRET not in str(exc.value)
    monkeypatch.delenv("TOKIWA_LLM__ANTHROPIC_API_KEYY")
    reset_settings_cache()
    assert get_settings() is not None  # strict with a clean configuration starts


def test_test_suite_configuration_is_clean(settings: Settings) -> None:
    """conftest's environment must not warn (it would hide real problems in every test log)."""
    assert config_issues(settings) == []


def test_startup_summary_masks_database_password(settings: Settings) -> None:
    s = settings.model_copy(
        update={
            "database": settings.database.model_copy(update={"url": "postgresql+asyncpg://u:pw-123@db/t"})
        }
    )
    line = startup_summary(s)
    assert "pw-123" not in line and "postgresql+asyncpg://u:***@db/t" in line and "llm.provider=mock" in line


# ----------------------------------------------------------------------------------------------- config show
def test_display_value_masks_secrets() -> None:
    assert display_value("url", "postgresql://user:pw@h:5432/db") == "postgresql://user:***@h:5432/db"
    assert (
        display_value("default_webhook_url", "https://hooks.slack.com/services/T/B/X")
        == "https://hooks.slack.com/***"
    )
    assert display_value("webhook_urls", {"soar": "https://soar.example/hook/abc?k=1"}) == {
        "soar": "https://soar.example/***?***"
    }
    assert display_value("ingest_token", "tkw_x") == "<set>"
    assert display_value("max_output_tokens", 8000) == 8000
    assert display_value("smtp_password_envs", ["TOKIWA_SMTP_PASSWORD"]) == ["TOKIWA_SMTP_PASSWORD"]
    assert display_value("base_url", "http://localhost:8788") == "http://localhost:8788"


def _cli(*args: str) -> tuple[int, str]:
    from tokiwa.cli import app

    result = CliRunner().invoke(app, ["config", "show", *args])
    return result.exit_code, result.output


def test_config_show_masks_and_reports_sources(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "tokiwa.yaml"
    cfg.write_text(
        "notify:\n  default_webhook_url: https://hooks.example.com/T0/PATH-SECRET\n", encoding="utf-8"
    )
    monkeypatch.setenv("TOKIWA_CONFIG", str(cfg))
    monkeypatch.setenv("TOKIWA_LLM__ANTHROPIC_API_KEY", SECRET)
    monkeypatch.setenv("TOKIWA_GATE__INGEST_TOKEN", "tkw_PLANTEDTOKEN")
    monkeypatch.setenv("TOKIWA_SERVER__SECRET_KEY", "x" * 40)
    monkeypatch.setenv("TOKIWA_LLM__PROVIDR", SECRET)
    code, out = _cli()
    assert code == 0, out
    for planted in (SECRET, "tkw_PLANTEDTOKEN", "x" * 40, "PATH-SECRET"):
        assert planted not in out
    assert 'llm.anthropic_api_key = "<set>"  [env (TOKIWA_LLM__ANTHROPIC_API_KEY)]' in out
    assert 'llm.provider = "mock"  [env (TOKIWA_LLM__PROVIDER)]' in out
    assert 'notify.default_webhook_url = "https://hooks.example.com/***"  [file]' in out
    assert "llm.max_output_tokens = 8000  [default]" in out
    assert "TOKIWA_LLM__PROVIDR" in out and f"{cfg} (loaded" in out

    code, out = _cli("--json", "--changed", "-s", "llm", "--check")
    assert code == 1  # a problem was found
    data = json.loads(out)
    assert {e["path"] for e in data["settings"]} >= {"llm.provider", "llm.anthropic_api_key"}
    assert all(e["path"].startswith("llm.") for e in data["settings"])
    assert [i["key"] for i in data["issues"]] == ["TOKIWA_LLM__PROVIDR"]
    assert SECRET not in out


def test_config_show_works_in_strict_mode_and_hides_invalid_input(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOKIWA_STRICT_CONFIG", "1")
    monkeypatch.setenv("TOKIWA_GATE__UPSTREAMM", "http://x")
    code, out = _cli("--check")
    assert code == 1 and "TOKIWA_GATE__UPSTREAMM" in out
    monkeypatch.setenv("TOKIWA_SERVER__SECRET_KEY", "short-PLANTED")  # rejected by the validator (< 32 chars)
    code, out = _cli()
    assert code == 2 and "server.secret_key" in out and "short-PLANTED" not in out


def test_config_show_db_reads_ui_overrides_without_creating_a_database(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_file = Path(settings.database.url.split("///", 1)[1])
    code, out = _cli("--db", "-s", "llm.model_fast")
    assert code == 0 and "database file not found" in out
    assert not db_file.exists()

    async def _store() -> None:
        from tokiwa.db.session import create_all, dispose_engine, init_engine
        from tokiwa.settings_store import set_setting

        init_engine()
        await create_all()
        await set_setting("llm.config", {"model_fast": "ui-model", "anthropic_api_key": SECRET})
        await dispose_engine()

    asyncio.run(_store())
    code, out = _cli("--db", "-s", "llm.model_fast", "-s", "llm.anthropic_api_key")
    assert code == 0, out
    assert 'llm.model_fast = "ui-model"  [ui (llm.config)]' in out
    assert 'llm.anthropic_api_key = "<set>"  [ui (llm.config)]' in out
    assert SECRET not in out


def test_effective_config_whole_section_json_counts_as_env(settings: Settings) -> None:
    env = {"TOKIWA_GATE": json.dumps({"sensor_id": "g-9"})}
    s = Settings.model_validate({**settings.model_dump(), "gate": {"sensor_id": "g-9"}})
    entry = next(e for e in effective_config(s, environ=env) if e.path == "gate.sensor_id")
    assert (entry.value, entry.source, entry.origin) == ("g-9", "env", "TOKIWA_GATE")


# ----------------------------------------------------------------------------------------------- *_FILE (#108)
def test_file_suffix_reads_string_settings_from_files(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "anthropic_api_key"
    key.write_text(SECRET + "\n", encoding="utf-8")
    url = tmp_path / "database_url"
    url.write_text("postgresql+asyncpg://tokiwa:pw-FILE@postgres:5432/tokiwa\n", encoding="utf-8")
    monkeypatch.setenv("TOKIWA_LLM__ANTHROPIC_API_KEY_FILE", str(key))
    monkeypatch.setenv("TOKIWA_LLM__ANTHROPIC_API_KEY", "")  # Compose "${X:-}" must not hide the file
    monkeypatch.delenv("TOKIWA_DATABASE__URL")
    monkeypatch.setenv("TOKIWA_DATABASE__URL_FILE", str(url))
    s = Settings()
    assert s.llm.anthropic_api_key is not None and s.llm.anthropic_api_key.get_secret_value() == SECRET
    assert s.database.url.endswith("@postgres:5432/tokiwa")
    assert env_issues(s) == []
    entries = {e.path: e for e in effective_config(s)}
    assert (entries["llm.anthropic_api_key"].value, entries["llm.anthropic_api_key"].origin) == (
        "<set>",
        "TOKIWA_LLM__ANTHROPIC_API_KEY_FILE",
    )
    assert "pw-FILE" not in json.dumps([e.value for e in entries.values()])


def test_file_suffix_errors_never_show_contents(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "k"
    key.write_text(SECRET, encoding="utf-8")
    monkeypatch.setenv("TOKIWA_LLM__ANTHROPIC_API_KEY_FILE", str(key))
    monkeypatch.setenv("TOKIWA_LLM__ANTHROPIC_API_KEY", "other-value")
    with pytest.raises(
        ValueError, match="both TOKIWA_LLM__ANTHROPIC_API_KEY and TOKIWA_LLM__ANTHROPIC_API_KEY_FILE"
    ):
        Settings()
    monkeypatch.delenv("TOKIWA_LLM__ANTHROPIC_API_KEY")
    monkeypatch.setenv("TOKIWA_LLM__ANTHROPIC_API_KEY_FILE", str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="cannot read") as exc:
        Settings()
    assert SECRET not in str(exc.value)
    code, out = _cli()
    assert code == 2 and "TOKIWA_LLM__ANTHROPIC_API_KEY_FILE: cannot read" in out


def test_file_suffix_only_for_string_settings_and_real_fields_win() -> None:
    issues = env_issues(environ={"TOKIWA_SERVER__PORT_FILE": "/x", "TOKIWA_GATE__TOKEN_FILE": "/run/t"})
    assert [i.key for i in issues] == ["TOKIWA_SERVER__PORT_FILE"]  # gate.token_file is a setting of its own
    assert "cannot be read from a file" in issues[0].problem


def test_anthropic_api_key_file_fallback(
    settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tokiwa.config import anthropic_api_key

    key = tmp_path / "key"
    key.write_text(SECRET + "\n", encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_API_KEY_FILE", str(key))
    assert anthropic_api_key(settings) == SECRET
    monkeypatch.setenv("ANTHROPIC_API_KEY", "direct")
    assert anthropic_api_key(settings) == "direct"
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    monkeypatch.setenv("ANTHROPIC_API_KEY_FILE", str(tmp_path / "missing"))
    assert anthropic_api_key(settings) is None
