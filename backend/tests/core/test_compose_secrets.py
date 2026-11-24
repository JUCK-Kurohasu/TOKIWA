"""Audits #71 / #108 / #110: which containers get which secrets (static checks of the shipped compose files).

Docker is not available in the test environment, so these read the YAML. ``docker compose config`` was used by hand
(docs/handoff/2026-11-23-audit-ops.md) to confirm how Compose resolves the bare ``KEY:`` entries.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from tokiwa.config import GateSettings

REPO = Path(__file__).resolve().parents[3]


def _compose(name: str) -> dict[str, Any]:
    return yaml.safe_load((REPO / name).read_text(encoding="utf-8"))


def test_gate_does_not_get_the_whole_env_file() -> None:
    doc = _compose("deploy/compose.yaml")
    gate, server = doc["services"]["gate"], doc["services"]["tokiwa"]
    assert "env_file" not in gate
    assert "env_file" not in doc["x-tokiwa-image"]
    assert server["env_file"][0]["path"] == "../.env"
    env = gate["environment"]
    for forbidden in ("SECRET_KEY", "ANTHROPIC", "OPENAI", "POSTGRES", "DATABASE", "INTEL", "NOTIFY"):
        assert not [k for k in env if forbidden in k], forbidden


def test_gate_forwards_every_gate_setting_from_env() -> None:
    """A gate setting missing here would silently not reach the gate container (it no longer gets .env)."""
    env = _compose("deploy/compose.yaml")["services"]["gate"]["environment"]
    missing = [f for f in GateSettings.model_fields if f"TOKIWA_GATE__{f.upper()}" not in env]
    assert missing == []


def test_lab_sensors_mount_only_their_own_token() -> None:
    services = _compose("lab/compose.yaml")["services"]
    for name, token_dir in (("gate", "gate"), ("agent", "agent"), ("sim-ingest", "sim")):
        mounts = [
            v for v in services[name]["volumes"] if isinstance(v, dict) and v.get("source") == "tokiwa-data"
        ]
        assert [m["volume"]["subpath"] for m in mounts] == [f"lab-tokens/{token_dir}"], name
        assert all(m["read_only"] for m in mounts)
        assert not [
            v for v in services[name]["volumes"] if isinstance(v, str) and v.startswith("tokiwa-data")
        ]
    assert (
        services["tokiwa"]["environment"]["ANTHROPIC_API_KEY"] is None
    )  # unset unless given (no empty variable)


def test_secrets_example_uses_file_variables() -> None:
    doc = _compose("deploy/compose.secrets.example.yaml")
    assert doc["services"]["tokiwa"]["environment"] == {
        "TOKIWA_LLM__ANTHROPIC_API_KEY_FILE": "/run/secrets/anthropic_api_key",
        "TOKIWA_DATABASE__URL_FILE": "/run/secrets/database_url",
    }
    assert doc["services"]["postgres"]["environment"] == {
        "POSTGRES_PASSWORD_FILE": "/run/secrets/postgres_password"
    }
    assert doc["services"]["gate"]["environment"] == {"TOKIWA_GATE__TOKEN_FILE": "/run/secrets/gate_token"}
    assert set(doc["secrets"]) == {"anthropic_api_key", "database_url", "postgres_password", "gate_token"}


def test_lab_and_postgres_hardening() -> None:
    """Audits #105 / #109: the lab gets deploy/compose.yaml's hardening; postgres drops capabilities."""
    lab = _compose("lab/compose.yaml")
    services = lab["services"]
    for name in ("tokiwa-init", "tokiwa", "gate", "sim", "sim-ingest", "agent", "victim"):
        svc = services[name] if name == "victim" else {**lab["x-tokiwa"], **services[name]}
        assert svc["read_only"] is True, name
        assert svc["cap_drop"] == ["ALL"], name
        assert "no-new-privileges:true" in svc["security_opt"], name
        assert svc["pids_limit"] > 0, name
    assert "no-new-privileges:true" in services["nginx"]["security_opt"]
    postgres = _compose("deploy/compose.yaml")["services"]["postgres"]
    assert postgres["cap_drop"] == ["ALL"]
    assert set(postgres["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}
    assert "no-new-privileges:true" in postgres["security_opt"]
