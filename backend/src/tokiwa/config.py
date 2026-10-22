"""TOKIWA configuration.

Static configuration is loaded from (highest priority first):

1. Environment variables prefixed with ``TOKIWA_`` (nested with ``__``, e.g. ``TOKIWA_LLM__DAILY_BUDGET_USD=5``)
2. A YAML file pointed to by ``TOKIWA_CONFIG`` (default: ``./tokiwa.yaml`` if it exists)
3. The defaults below

Runtime-editable settings (changed from the UI) are stored in the ``settings_kv`` table and overlaid by the
service that owns them (e.g. ``tokiwa.llm.settings``). Each module owns exactly one section class below;
add fields to *your own* section only, so parallel work does not conflict.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict


class ServerSettings(BaseModel):
    host: str = "0.0.0.0"  # noqa: S104 - server is meant to be reachable inside the lab network
    port: int = 8788
    base_url: str = "http://localhost:8788"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    # Built frontend (vite build output). Served at "/" when the directory exists.
    static_dir: Path | None = None
    data_dir: Path = Path("./data")
    # JWT signing secret. Generated and persisted to data_dir/secret.key on first boot when unset.
    secret_key: SecretStr | None = None
    token_ttl_minutes: int = 60 * 12


class DatabaseSettings(BaseModel):
    # SQLite (default, lab scale) or PostgreSQL: postgresql+asyncpg://user:pass@host/db
    url: str = "sqlite+aiosqlite:///./data/tokiwa.db"
    echo: bool = False


class RedactionSettings(BaseModel):
    enabled: bool = True
    # Header names (case-insensitive) whose values are always masked before storage / LLM submission.
    sensitive_headers: list[str] = Field(
        default_factory=lambda: [
            "authorization",
            "cookie",
            "set-cookie",
            "proxy-authorization",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
        ]
    )
    mask_emails: bool = True
    mask_ips: bool = False  # source IPs are usually needed for analysis; enable for privacy-sensitive labs
    max_field_chars: int = 2048


class LLMSettings(BaseModel):
    # "auto": anthropic if an API key is configured, otherwise mock.
    provider: Literal["auto", "anthropic", "openai_compat", "mock"] = "auto"
    anthropic_api_key: SecretStr | None = None  # falls back to ANTHROPIC_API_KEY
    anthropic_base_url: str | None = None
    # OpenAI-compatible endpoint (e.g. a local Ollama / vLLM) for privacy-sensitive deployments.
    openai_base_url: str | None = None
    openai_api_key: SecretStr | None = None
    # Tiering: cheap model for first-pass triage, strong model for escalation / deep analysis.
    model_fast: str = "claude-haiku-5-5"
    model_deep: str = "claude-opus-5-5"
    effort_fast: Literal["low", "medium", "high", "xhigh", "max"] = "low"
    effort_deep: Literal["low", "medium", "high", "xhigh", "max"] = "medium"
    max_output_tokens: int = 4096
    max_input_tokens_per_call: int = 24_000
    daily_budget_usd: float = 5.0
    # Server-side refusal fallback (security content can trip safety classifiers).
    enable_fallbacks: bool = True
    prompt_cache: bool = True
    output_language: Literal["ja", "en"] = "ja"
    request_timeout_seconds: float = 120.0
    # USD per 1M tokens, overrides/extends the built-in table: {"model": {"input": x, "output": y}}
    pricing: dict[str, dict[str, float]] = Field(default_factory=dict)
    redaction: RedactionSettings = Field(default_factory=RedactionSettings)


class DetectionSettings(BaseModel):
    disabled_detectors: list[str] = Field(default_factory=list)
    sigma_rule_dirs: list[Path] = Field(default_factory=lambda: [Path("../rules/sigma")])
    dedup_window_seconds: int = 300
    # Paths of LLM-backed applications protected by TOKIWA (prompt-injection detection applies here).
    llm_app_paths: list[str] = Field(default_factory=lambda: ["/api/chat", "/v1/chat/completions", "/chat"])
    session_idle_timeout_seconds: int = 1800
    # Score (0..1) above which a session is considered AI-agent driven.
    ai_agent_threshold: float = 0.7


class TriageSettings(BaseModel):
    auto_triage: bool = True
    # Alerts below this severity are not sent to the LLM automatically (cost control).
    min_severity_for_llm: Literal["info", "low", "medium", "high", "critical"] = "medium"
    # Fast-tier confidence below this, or severity >= escalate_severity, escalates to the deep tier.
    escalate_confidence_below: float = 0.6
    escalate_severity: Literal["low", "medium", "high", "critical"] = "high"
    max_concurrent: int = 4
    incident_window_minutes: int = 60
    max_evidence_events: int = 25


class IntelSettings(BaseModel):
    enabled: bool = True
    sync_interval_minutes: int = 360
    sources: dict[str, bool] = Field(
        default_factory=lambda: {
            "kev": True,
            "epss": True,
            "nvd": True,
            "osv": True,
            "jvn": True,
            "ghsa": True,
            "rss": True,
        }
    )
    nvd_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    rss_feeds: list[str] = Field(
        default_factory=lambda: [
            "https://www.jpcert.or.jp/rss/jpcert.rdf",
            "https://www.ipa.go.jp/security/alert-rss.rdf",
            "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.bleepingcomputer.com/feed/",
        ]
    )
    # LLM web research for fresh 0-day / exploitation reports (uses Claude's server-side web search).
    research_enabled: bool = True
    research_interval_hours: int = 12
    research_topics: list[str] = Field(
        default_factory=lambda: [
            "actively exploited zero-day vulnerabilities disclosed in the last 48 hours",
            "AI-driven / LLM-agent cyber attack campaigns and techniques reported recently",
        ]
    )
    epss_alert_threshold: float = 0.1
    nvd_lookback_days: int = 3


class ResponseSettings(BaseModel):
    # Safety: nothing is executed without human approval unless explicitly enabled per action type.
    auto_approve_enabled: bool = False
    auto_approve_actions: list[str] = Field(default_factory=list)
    default_ttl_minutes: int = 60
    max_ttl_minutes: int = 60 * 24 * 7
    nftables_enabled: bool = False
    # Never block these (CIDRs). Protects against self-lockout.
    protected_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.0/8", "::1/128"])


class DeceptionSettings(BaseModel):
    enabled: bool = True
    ai_canaries: bool = True
    decoy_paths: list[str] = Field(
        default_factory=lambda: [
            "/.env",
            "/backup.sql",
            "/admin/config.php",
            "/.git/config",
            "/api/internal/debug",
        ]
    )
    labyrinth_enabled: bool = False
    labyrinth_max_depth: int = 8


class GateSettings(BaseModel):
    """TOKIWA Gate: reverse-proxy sensor / enforcer (runs as a separate process)."""

    listen_host: str = "0.0.0.0"  # noqa: S104
    listen_port: int = 8080
    upstream: str = "http://127.0.0.1:3000"
    server_url: str = "http://127.0.0.1:8788"
    ingest_token: SecretStr | None = None
    sensor_id: str = "gate-1"
    capture_body_bytes: int = 4096
    batch_size: int = 100
    flush_interval_seconds: float = 1.0
    policy_refresh_seconds: float = 5.0
    trust_forwarded_for: bool = False


class AgentSettings(BaseModel):
    """TOKIWA Agent: host sensor process that pushes telemetry to the server."""

    server_url: str = "http://127.0.0.1:8788"
    ingest_token: SecretStr | None = None
    sensor_id: str | None = None  # defaults to hostname
    interval_seconds: float = 10.0
    host_sensor: bool = True
    nginx_json_logs: list[Path] = Field(default_factory=list)
    caddy_json_logs: list[Path] = Field(default_factory=list)
    suricata_eve_logs: list[Path] = Field(default_factory=list)
    zeek_log_dirs: list[Path] = Field(default_factory=list)


class NotifySettings(BaseModel):
    # Minimal env-configured default channel; richer channels are managed in the DB/UI.
    default_webhook_url: str | None = None
    default_min_severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    public_ui_url: str | None = None


class CopilotSettings(BaseModel):
    enabled: bool = True
    max_tool_iterations: int = 8
    max_history_messages: int = 40
    # Interactive Q&A with multi-step tool use benefits from the strong model; "fast" trades quality for cost.
    tier: Literal["fast", "deep"] = "deep"
    # Upper bound (chars of JSON) for one tool result handed to the LLM. Lists are trimmed to fit.
    max_tool_result_chars: int = 12_000


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TOKIWA_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    env: Literal["dev", "prod", "test"] = "dev"
    log_level: str = "INFO"
    server: ServerSettings = Field(default_factory=ServerSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    triage: TriageSettings = Field(default_factory=TriageSettings)
    intel: IntelSettings = Field(default_factory=IntelSettings)
    response: ResponseSettings = Field(default_factory=ResponseSettings)
    deception: DeceptionSettings = Field(default_factory=DeceptionSettings)
    gate: GateSettings = Field(default_factory=GateSettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    notify: NotifySettings = Field(default_factory=NotifySettings)
    copilot: CopilotSettings = Field(default_factory=CopilotSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings, env_settings, dotenv_settings, _YamlSource(settings_cls), file_secret_settings)


class _YamlSource(PydanticBaseSettingsSource):
    def _load(self) -> dict[str, Any]:
        path = Path(os.environ.get("TOKIWA_CONFIG", "tokiwa.yaml"))
        if not path.is_file():
            return {}
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{path}: top-level YAML must be a mapping")
        return data

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:  # pragma: no cover
        return self._load().get(field_name), field_name, False

    def __call__(self) -> dict[str, Any]:
        return self._load()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """For tests: force settings to be re-read from the environment."""
    get_settings.cache_clear()


def anthropic_api_key(settings: Settings | None = None) -> str | None:
    s = settings or get_settings()
    if s.llm.anthropic_api_key is not None:
        return s.llm.anthropic_api_key.get_secret_value() or None
    return os.environ.get("ANTHROPIC_API_KEY") or None
