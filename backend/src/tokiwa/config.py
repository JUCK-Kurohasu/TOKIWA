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
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

MIN_SECRET_KEY_LENGTH = 32


class ServerSettings(BaseModel):
    host: str = "0.0.0.0"  # noqa: S104 - server is meant to be reachable inside the lab network
    port: int = 8788
    base_url: str = "http://localhost:8788"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    # Built frontend (vite build output). Served at "/" when the directory exists.
    static_dir: Path | None = None
    data_dir: Path = Path("./data")
    # JWT signing secret. Generated and persisted to data_dir/secret.key on first boot when unset. An empty value
    # counts as unset; a set value must have at least MIN_SECRET_KEY_LENGTH characters (HS256 keys can be guessed
    # offline from any issued JWT, and a forged JWT is an admin login).
    secret_key: SecretStr | None = None
    token_ttl_minutes: int = 60 * 12
    # Request body size limits enforced by the app itself (413), independent of any reverse proxy.
    # Ingest batches are large by design (Gate: 100 events, agent: 500, server max 5000 per request); a worst-case
    # Gate batch (64 headers x 2 KiB each per event) is about 15 MB. Shippers DROP a batch answered with 413.
    max_body_bytes: int = Field(default=1024 * 1024, ge=1024)
    max_ingest_body_bytes: int = Field(default=32 * 1024 * 1024, ge=1024)
    # Serve the unauthenticated Swagger UI (/api/docs) and OpenAPI document (/api/openapi.json).
    # True keeps existing setups and docs working; set false in production (they map the API for scanners).
    expose_docs: bool = True
    # CSP / X-Frame-Options / nosniff / Referrer-Policy on every response (tokiwa.api.middleware). Turn off only
    # if a reverse proxy sets its own policy or a customised UI needs a different CSP.
    security_headers: bool = True

    @field_validator("secret_key", mode="before")
    @classmethod
    def _empty_secret_is_unset(cls, value: Any) -> Any:
        raw = value.get_secret_value() if isinstance(value, SecretStr) else value
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return None
        if isinstance(raw, str) and len(raw.strip()) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(
                f"server.secret_key must have at least {MIN_SECRET_KEY_LENGTH} characters "
                "(e.g. `openssl rand -base64 48`), or leave it unset to use the generated data_dir/secret.key"
            )
        return value  # used verbatim (stripping would change existing keys and log everyone out)


class AuthSettings(BaseModel):
    """Login and first-run setup protection (owned by tokiwa.auth / routes/auth.py)."""

    # POST /auth/setup (the unauthenticated "create the first admin" call) requires the one-time code that the
    # server writes to data_dir/setup-code and to its log while setup is pending. Disable only on a host that no
    # one else can reach before setup (or create the first admin with `tokiwa user create --role admin`).
    setup_code_required: bool = True
    # Login throttling (state in the database, shared by all workers). Within a sliding window of
    # login_lockout_minutes, a user name + source IP pair is refused (429) after login_max_failures failures, and a
    # source IP after login_max_failures_per_ip failures over any user names (password spraying). 0 disables a limit.
    login_max_failures: int = Field(default=5, ge=0)
    login_max_failures_per_ip: int = Field(default=30, ge=0)
    login_lockout_minutes: float = Field(default=15.0, gt=0)
    # Password hashing (scrypt, ~16 MiB and tens of ms each) runs in worker threads; at most this many at a time,
    # so a burst of logins cannot starve ingest / SSE on the event loop or exhaust memory.
    password_hash_concurrency: int = Field(default=4, ge=1)


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
    # Thinking cannot be disabled on the deep model and counts against max_tokens.
    max_output_tokens: int = 8000
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


class WebDetectionSettings(BaseModel):
    """detect-web: knobs for ``tokiwa.detect.detectors.web_*`` (catalog: docs/detection/web.md)."""

    # Per-field cap before decoding (ReDoS / CPU guard). Gate captures 4 KiB of body by default.
    max_inspect_chars: int = 8192
    # web.error_burst: 4xx storm from one source (directory brute force)
    error_burst_window_seconds: float = 60.0
    error_burst_min_errors: int = 30
    error_burst_min_ratio: float = 0.6
    error_burst_min_unique_paths: int = 15
    # web.credential_stuffing: auth failures against login-like paths
    login_path_regex: str = (
        r"(?:^|/)(?:login|log-in|signin|sign-in|sign_in|logon|auth|authenticate|session|sessions|token"
        r"|wp-login\.php|xmlrpc\.php|j_security_check)(?:$|[/.?;_-])"
    )
    credential_window_seconds: float = 300.0
    credential_fail_statuses: list[int] = Field(default_factory=lambda: [401, 403])
    credential_min_failures: int = 10
    credential_min_unique_users: int = 4
    # web.request_flood: sustained requests/second from one source
    flood_window_seconds: float = 10.0
    flood_max_rps: float = 20.0
    # web.rare_method: methods that never alert (add WebDAV verbs here for DAV deployments)
    allowed_methods: list[str] = Field(
        default_factory=lambda: ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    )


def default_sigma_rule_dirs(package_file: Path | None = None, prefix: Path | None = None) -> list[Path]:
    """Where the shipped Sigma rule set lives, independent of the process CWD (#177).

    The old default ``../rules/sigma`` was resolved against the CWD (with ``backend/`` as a fallback derived from
    the loader's own location), so a copied or non-editable install started from another directory silently ran
    without any Sigma rule. Fallback order now (first existing directory wins):

    1. source checkout: ``<repo>/rules/sigma`` when ``tokiwa`` is imported from ``<repo>/backend/src/tokiwa``
       (``uv sync`` installs the project editable: development, CI, ``tokiwa eval``);
    2. installed layout: ``<virtualenv>/../rules/sigma``. The Docker image keeps the venv in ``/app/.venv`` and the
       rules in ``/app/rules/sigma`` (deploy/Dockerfile, which also sets TOKIWA_DETECTION__SIGMA_RULE_DIRS).

    When neither exists (e.g. a wheel installed elsewhere) the first candidate is returned anyway, so the loader
    reports it as missing (ERROR at startup) instead of quietly evaluating without Sigma rules. An explicit
    ``detection.sigma_rule_dirs`` always wins; the loader resolves relative entries against the CWD and then
    ``backend/`` as before, so existing configs keep working.
    """
    pkg = (package_file or Path(__file__)).resolve().parent  # .../tokiwa
    candidates: list[Path] = []
    if pkg.parent.name == "src":
        candidates.append(pkg.parents[2] / "rules" / "sigma")
    candidates.append(Path(prefix or sys.prefix).resolve().parent / "rules" / "sigma")
    return [next((c for c in candidates if c.is_dir()), candidates[0])]


class DetectionSettings(BaseModel):
    disabled_detectors: list[str] = Field(default_factory=list)
    # Absolute path resolved from the package location; see default_sigma_rule_dirs().
    sigma_rule_dirs: list[Path] = Field(default_factory=lambda: default_sigma_rule_dirs())
    dedup_window_seconds: int = 300
    # Paths of LLM-backed applications protected by TOKIWA (prompt-injection detection applies here).
    llm_app_paths: list[str] = Field(default_factory=lambda: ["/api/chat", "/v1/chat/completions", "/chat"])
    session_idle_timeout_seconds: int = 1800
    # Score (0..1) above which a session is considered AI-agent driven.
    ai_agent_threshold: float = 0.7
    web: WebDetectionSettings = Field(default_factory=WebDetectionSettings)


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
    # nft binary used by the nftables_block executor (fixed argv template, never a shell).
    nftables_binary: str = "nft"
    # Never block these (CIDRs). Protects against self-lockout.
    protected_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.0/8", "::1/128"])
    # Also treat this server's own interface addresses as protected.
    protect_server_addresses: bool = True
    # Reject private / ULA / link-local targets (e.g. management networks). Off by default: lab attackers
    # usually live on private networks.
    block_private_targets: bool = False
    # Refuse targets broader than these prefixes (e.g. 0.0.0.0/0) for gate/nftables actions.
    min_prefix_v4: int = 16
    min_prefix_v6: int = 48
    default_rate_limit_rpm: int = 60
    default_tarpit_delay_ms: int = 2000
    # webhook executor: named endpoints. Actions select a *name* (params.endpoint), never a URL.
    webhook_urls: dict[str, str] = Field(default_factory=dict)
    # Allowed destination hosts ("example.com" exact, ".example.com" suffix). Empty = any host.
    webhook_allowed_hosts: list[str] = Field(default_factory=list)
    # SSRF guard: refuse destinations resolving to private / loopback / link-local / reserved addresses.
    webhook_block_private: bool = True
    webhook_timeout_seconds: float = 10.0


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
    # Where the labyrinth is served (prefix). Requests below it are labyrinth trips.
    labyrinth_prefix: str = "/archive/"
    # Append the hidden AI-canary snippet to upstream text/html responses (GatePolicy.html_injection).
    # Disable when the protected app ships its own DOM back to the server (session replay etc.).
    html_injection: bool = True
    # Where the Gate inserts it: "head" (HTML comment only, right after <head>), "body_start" (after <body>),
    # "body_end" (before </body>, the only position before audit #41). Tools of AI agents often keep only the first
    # N characters of a page (ARTEX: 30,000), so a snippet only at the end of a large page is never read.
    html_injection_positions: list[Literal["head", "body_start", "body_end"]] = Field(
        default=["body_start", "body_end"], min_length=1  # pydantic copies mutable defaults per instance
    )
    # Header the AI-canary instruction asks agents to send. Must NOT be listed in
    # llm.redaction.sensitive_headers, otherwise its value is masked before detection can see it.
    canary_header: str = "X-Debug-Auth"
    # Language of the hidden instructions and labyrinth pages.
    canary_language: Literal["ja", "en", "both"] = "both"
    # Trips whose request carries browser cross-site / sub-resource signals (Sec-Fetch-Site cross-site/same-site,
    # Sec-Fetch-Dest image/script/..., prefetch, foreign Origin/Referer) are recorded as "induced": low severity,
    # no AI attribution, never a block basis - a third-party page can make any visitor send them (audit #133).
    # A client can claim these headers itself to lower its trips to low (still alerted); false = old behaviour.
    downgrade_browser_induced: bool = True


class GateSettings(BaseModel):
    """TOKIWA Gate: reverse-proxy sensor / enforcer (runs as a separate process)."""

    listen_host: str = "0.0.0.0"  # noqa: S104
    listen_port: int = 8080
    upstream: str = "http://127.0.0.1:3000"
    server_url: str = "http://127.0.0.1:8788"
    ingest_token: SecretStr | None = None
    # File holding the token (preferred). Re-read when it changes and after a 401, so a rotated token is
    # picked up without restarting the gate. Takes precedence over ingest_token when readable.
    token_file: Path | None = None
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
    # Collect ESTABLISHED / SYN_RECV connections (new ones since the previous poll -> CONNECTION events).
    connections: bool = True
    max_connections_per_cycle: int = 1000
    # Skip unconnected UDP sockets on ephemeral ports (client sockets; would make PORT_CHANGE noisy).
    udp_ignore_ephemeral: bool = True
    # Where log tailing starts on first open: "end" (only new lines) or "beginning" (replay the file).
    log_start_at: Literal["end", "beginning"] = "end"
    log_poll_seconds: float = 1.0
    # Shipper: events per POST (server max 5000), in-memory buffer cap while the server is unreachable.
    batch_size: int = 500
    max_buffer_events: int = 50_000
    max_retries: int = 3
    verify_tls: bool = True
    # --- server-side knobs for host telemetry (read by enrich/ports.py and detectors/net_port_scan.py) ---
    # First PORT_SNAPSHOT from an unknown host: "info" emits PORT_CHANGE(opened) marked initial (alerts at
    # info severity), "learn" silently records the listeners as the host's starting state.
    ports_first_snapshot: Literal["info", "learn"] = "info"
    scan_window_seconds: float = 60.0
    scan_port_threshold: int = 20  # distinct destination ports from one source within the window
    scan_host_threshold: int = 10  # distinct destination hosts from one source within the window


class NotifySettings(BaseModel):
    # Minimal env-configured default channel; richer channels are managed in the DB/UI.
    default_webhook_url: str | None = None
    default_min_severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    public_ui_url: str | None = None
    # Message language: Japanese, English, or both (ja first).
    language: Literal["ja", "en", "both"] = "both"
    # Same target (source IP / incident / action target) is notified at most once per N minutes,
    # unless the severity went up.
    dedup_minutes: int = 10
    # Send approval requests for new response proposals (action.proposed).
    notify_action_proposals: bool = True
    # Allowed destination hosts for webhook/slack/discord ("example.com" exact, ".example.com" suffix).
    # Empty = any host.
    allowed_hosts: list[str] = Field(default_factory=list)
    # SSRF guard: refuse destinations resolving to private / loopback / link-local / reserved addresses.
    # Disable for lab receivers on a private network.
    block_private_destinations: bool = True
    http_timeout_seconds: float = 10.0


class CopilotSettings(BaseModel):
    enabled: bool = True
    max_tool_iterations: int = 8
    max_history_messages: int = 40
    # Interactive Q&A with multi-step tool use benefits from the strong model; "fast" trades quality for cost.
    tier: Literal["fast", "deep"] = "deep"
    # Upper bound (chars of JSON) for one tool result handed to the LLM. Lists are trimmed to fit.
    max_tool_result_chars: int = 12_000
    # Audit #164: each message can drive up to max_tool_iterations deep-tier calls against the shared daily
    # budget. Minimum role to start conversations / send messages (viewers can still read their old ones).
    min_role: Literal["viewer", "analyst", "admin"] = "analyst"
    # Per-user messages per minute (0 = unlimited).
    messages_per_minute: int = 6


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TOKIWA_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    env: Literal["dev", "prod", "test"] = "dev"
    log_level: str = "INFO"
    server: ServerSettings = Field(default_factory=ServerSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
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
