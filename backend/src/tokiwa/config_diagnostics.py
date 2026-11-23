"""Configuration diagnostics and the effective-configuration view (audit #161).

Why this exists: :class:`tokiwa.config.Settings` ignores unknown input (``extra="ignore"``, and the section models
ignore unknown keys too), so a misspelt ``TOKIWA_RESPONSE__PROTECTED_CIDR`` or a ``tokiwa.yml`` that is never read
used to leave TOKIWA running on the defaults without a word - and the settings that tighten security are exactly the
ones whose defaults are the permissive side. Rejecting unknown input outright would break every deployment that keeps
Compose variables in the same ``.env`` file, so the checks here *report* instead (WARNING at startup, fatal only with
``TOKIWA_STRICT_CONFIG=1``) and ``tokiwa config show`` lets operators see what is actually in effect.

Rules:

- Messages carry names and paths only, never values: the variable someone misspelt is often an API key.
- ``TOKIWA_*`` variables are resolved like pydantic-settings does (case-insensitive, ``__`` between levels).
  A ``dict`` field accepts any sub-key; a list or scalar field cannot be nested into.
- Variables that are not settings but are read by other parts of TOKIWA (healthcheck, lab scripts, Compose
  interpolation, e-mail password variables) are listed in :data:`OPERATIONAL_ENV_VARS`. A name that is used by a new
  script must be added there, otherwise every deployment that passes it in warns.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import types
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, Union, get_args, get_origin
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, SecretStr
from pydantic_core import to_jsonable_python

from tokiwa.config import CONFIG_ENV, STRICT_CONFIG_ENV, Settings, config_file_path, load_config_file

ENV_PREFIX = "TOKIWA_"
NESTED = "__"

# TOKIWA_* names that are not Settings fields. Keep in sync with the readers named in the comments.
OPERATIONAL_ENV_VARS: frozenset[str] = frozenset(
    {
        CONFIG_ENV,
        STRICT_CONFIG_ENV,
        "TOKIWA_NO_JOBS",  # tokiwa serve --no-jobs -> api/asgi.py
        "TOKIWA_HEALTHCHECK_URL",  # deploy/healthcheck.py
        "TOKIWA_HEALTHCHECK_TIMEOUT",
        "TOKIWA_TOKEN_FILE",  # lab/scripts/with-token.sh
        "TOKIWA_TOKEN_ENV",
        "TOKIWA_LAB_TOKEN_DIR",  # lab/scripts/init-tokens.sh
        "TOKIWA_SIM_TOKEN",  # tokiwa sim ingest
        "TOKIWA_URL",  # scripts/seed_demo.py
        "TOKIWA_INGEST_TOKEN",
        "TOKIWA_IMAGE",  # deploy/compose.yaml interpolation (also reaches the containers through .env)
        "TOKIWA_BIND",
        "TOKIWA_PORT",
        "TOKIWA_GATE_BIND",
        "TOKIWA_GATE_PORT",
        "TOKIWA_BACKEND",  # scripts/dev.sh, frontend/vite.config.ts
        "TOKIWA_BACKEND_PORT",
        "TOKIWA_FRONTEND_PORT",
        "TOKIWA_UID",  # deploy/Dockerfile build arguments
        "TOKIWA_GID",
        "TOKIWA_EXTRAS",
        "TOKIWA_VERSION",
    }
)
# E-mail channel password variables (tokiwa.notify.channels.ALLOWED_PASSWORD_ENV_PREFIXES) and the names listed in
# notify.smtp_password_envs are read by name at send time.
OPERATIONAL_ENV_PREFIXES: tuple[str, ...] = ("TOKIWA_NOTIFY_SMTP_", "TOKIWA_SMTP_PASSWORD")

Source = Literal["env", "file", "default", "ui"]


@dataclass(frozen=True)
class ConfigIssue:
    """One configuration problem. ``key`` is a variable name, a dotted YAML path or the config file path."""

    source: Literal["env", "file"]
    key: str
    problem: str
    hint: str | None = None

    def __str__(self) -> str:
        text = f"{self.key}: {self.problem}"
        return f"{text} ({self.hint})" if self.hint else text


# ---------------------------------------------------------------------------------------------------------
# Model walking
# ---------------------------------------------------------------------------------------------------------
def _unwrap(annotation: Any) -> Any:
    """Strip ``Annotated`` and ``Optional`` (a union with ``None``) from a field annotation."""
    while True:
        origin = get_origin(annotation)
        if origin is Annotated:
            annotation = get_args(annotation)[0]
            continue
        if origin is Union or origin is types.UnionType:
            args = [a for a in get_args(annotation) if a is not type(None)]
            if len(args) == 1:
                annotation = args[0]
                continue
        return annotation


def section_model(annotation: Any) -> type[BaseModel] | None:
    """The model class of a nested section field, ``None`` for leaves."""
    inner = _unwrap(annotation)
    if isinstance(inner, type) and issubclass(inner, BaseModel):
        return inner
    return None


def _is_mapping(annotation: Any) -> bool:
    inner = _unwrap(annotation)
    origin = get_origin(inner) or inner
    return isinstance(origin, type) and issubclass(origin, Mapping)


def _suggest(name: str, candidates: list[str]) -> str | None:
    lowered = {c.lower(): c for c in candidates}
    if name.lower() in lowered:
        return lowered[name.lower()]
    match = difflib.get_close_matches(name.lower(), list(lowered), n=1, cutoff=0.6)
    return lowered[match[0]] if match else None


def _env_name(path: tuple[str, ...]) -> str:
    return ENV_PREFIX + NESTED.join(p.upper() for p in path)


@dataclass
class _Resolved:
    path: tuple[str, ...] = ()
    error: str | None = None
    hint: str | None = None


def _resolve_env(name: str) -> _Resolved:
    """Map ``TOKIWA_A__B__C`` onto a field path of :class:`Settings` (case-insensitive, like pydantic-settings)."""
    parts = name[len(ENV_PREFIX) :].lower().split(NESTED)
    model: type[BaseModel] = Settings
    path: tuple[str, ...] = ()
    for i, part in enumerate(parts):
        fields = model.model_fields
        if part not in fields:
            where = "a setting" if not path else f"a field of {'.'.join(path)}"
            res = _Resolved(path, f"{part!r} is not {where}: ignored")
            close = _suggest(part, list(fields))
            if close is not None:
                res.hint = f"did you mean {_env_name((*path, close))}?"
            elif not path and len(parts) == 1:
                res.hint = _single_underscore_hint(part)
            return res
        path = (*path, part)
        if i == len(parts) - 1:
            return _Resolved(path)
        sub = section_model(fields[part].annotation)
        if sub is None:
            if _is_mapping(fields[part].annotation):
                return _Resolved(path)  # dict field: any sub-key is data
            return _Resolved(path, f"{'.'.join(path)} has no sub-settings: ignored")
        model = sub
    return _Resolved(path)  # pragma: no cover - loop always returns


def _single_underscore_hint(part: str) -> str | None:
    """``TOKIWA_LLM_PROVIDER`` -> ``did you mean TOKIWA_LLM__PROVIDER?`` (one underscore instead of two)."""
    for section, info in Settings.model_fields.items():
        sub = section_model(info.annotation)
        if sub is None or not part.startswith(section + "_"):
            continue
        rest = part[len(section) + 1 :]
        close = _suggest(rest, list(sub.model_fields))
        if close is not None:
            return f"did you mean {_env_name((section, close))}? nested settings use two underscores"
    return None


def _is_operational(name: str, settings: Settings | None) -> bool:
    upper = name.upper()
    if upper in OPERATIONAL_ENV_VARS or upper.startswith(OPERATIONAL_ENV_PREFIXES):
        return True
    return settings is not None and name in settings.notify.smtp_password_envs


def _tokiwa_env(environ: Mapping[str, str]) -> Iterator[str]:
    for name in sorted(environ):
        if name.upper().startswith(ENV_PREFIX):
            yield name


# ---------------------------------------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------------------------------------
def env_issues(
    settings: Settings | None = None, environ: Mapping[str, str] | None = None
) -> list[ConfigIssue]:
    env = os.environ if environ is None else environ
    issues: list[ConfigIssue] = []
    for name in _tokiwa_env(env):
        if _is_operational(name, settings):
            continue
        res = _resolve_env(name)
        if res.error is not None:
            issues.append(ConfigIssue("env", name, res.error, res.hint))
    return issues


def _yaml_issues(model: type[BaseModel], data: Mapping[Any, Any], prefix: str) -> Iterator[ConfigIssue]:
    fields = model.model_fields
    for key, value in data.items():
        dotted = f"{prefix}{key}"
        if not isinstance(key, str):
            yield ConfigIssue("file", dotted, "keys must be strings: ignored")
            continue
        if key in fields:
            sub = section_model(fields[key].annotation)
            if sub is not None and isinstance(value, Mapping):
                yield from _yaml_issues(sub, value, f"{dotted}.")
            continue
        close = _suggest(key, list(fields))
        hint = f"did you mean {prefix}{close}?" if close is not None else None
        if close is not None and close.lower() == key.lower():
            hint = f"keys are case-sensitive: {prefix}{close}"
        yield ConfigIssue("file", dotted, "unknown key: ignored", hint)


def file_issues() -> list[ConfigIssue]:
    """Problems with the config file itself, then unknown keys in it."""
    path, explicit = config_file_path()
    if path is None:
        return []
    shown = str(path)
    if path.is_dir():
        return [
            ConfigIssue(
                "file",
                shown,
                "is a directory, so no settings were read from a file",
                "a Docker bind mount whose source file is missing creates a directory; check the host path",
            )
        ]
    if not path.exists():
        if not explicit:
            return []  # ./tokiwa.yaml is optional
        return [
            ConfigIssue(
                "file",
                shown,
                f"{CONFIG_ENV} names a file that does not exist, so no settings were read from a file",
                f"fix the path, or set {CONFIG_ENV}= (empty) to run on environment variables only",
            )
        ]
    if not path.is_file():
        return [ConfigIssue("file", shown, "is not a regular file, so no settings were read from it")]
    prefix = f"{shown}: "
    return [
        ConfigIssue(i.source, prefix + i.key, i.problem, i.hint)
        for i in _yaml_issues(Settings, load_config_file(), "")
    ]


def config_issues(
    settings: Settings | None = None, environ: Mapping[str, str] | None = None
) -> list[ConfigIssue]:
    return file_issues() + env_issues(settings, environ)


# ---------------------------------------------------------------------------------------------------------
# Effective configuration (tokiwa config show)
# ---------------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ConfigEntry:
    path: str
    value: Any  # JSON-safe, secrets masked
    source: Source
    origin: str | None = None  # env var name / config file / "llm.config"
    default: bool = field(default=True)


MASK = "<set>"
_SECRET_NAME = re.compile(r"(^|_)(api_key|key|token|password|passwd|secret|credentials?)$")


def _mask_url(text: str, *, hide_path: bool) -> str:
    try:
        parts = urlsplit(text)
    except ValueError:
        return MASK
    if not parts.scheme or not parts.netloc:
        return MASK if hide_path else text
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, _, host = netloc.rpartition("@")
        user = userinfo.split(":", 1)[0]
        netloc = f"{user}:***@{host}" if ":" in userinfo else f"{user}@{host}"
    path = "/***" if hide_path and parts.path not in ("", "/") else parts.path
    query = "***" if parts.query else ""
    return urlunsplit((parts.scheme, netloc, path, query, ""))


def _mask_value(name: str, value: Any) -> Any:
    hide_path = "webhook" in name
    if isinstance(value, str):
        if "://" in value or hide_path:
            return _mask_url(value, hide_path=hide_path)
        return value
    if isinstance(value, dict):
        return {k: _mask_value(name, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_value(name, v) for v in value]
    return value


def display_value(name: str, value: Any) -> Any:
    """JSON-safe value for display: secrets replaced by ``<set>``, URL passwords / queries / webhook paths hidden."""
    if isinstance(value, SecretStr):
        return MASK if value.get_secret_value() else ""
    if value is None:
        return None
    if _SECRET_NAME.search(name) and value != "":
        return MASK
    return _mask_value(name, to_jsonable_python(value, fallback=str))


def _leaves(obj: BaseModel, prefix: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any, Any]]:
    for name, info in type(obj).model_fields.items():
        value = getattr(obj, name)
        path = (*prefix, name)
        if isinstance(value, BaseModel):
            yield from _leaves(value, path)
        else:
            yield path, value, info.get_default(call_default_factory=True)


def _file_paths(
    model: type[BaseModel], data: Mapping[Any, Any], prefix: tuple[str, ...]
) -> Iterator[tuple[str, ...]]:
    fields = model.model_fields
    for key, value in data.items():
        if not isinstance(key, str) or key not in fields:
            continue
        sub = section_model(fields[key].annotation)
        if sub is not None and isinstance(value, Mapping):
            yield from _file_paths(sub, value, (*prefix, key))
        else:
            yield (*prefix, key)


def _env_paths(environ: Mapping[str, str]) -> dict[tuple[str, ...], str]:
    """Leaf path -> the variable that sets it (a whole-section JSON variable covers the keys it contains)."""
    out: dict[tuple[str, ...], str] = {}
    for name in _tokiwa_env(environ):
        res = _resolve_env(name)
        if res.error is not None or not res.path:
            continue
        model: type[BaseModel] = Settings
        for part in res.path[:-1]:
            sub = section_model(model.model_fields[part].annotation)
            assert sub is not None
            model = sub
        sub = section_model(model.model_fields[res.path[-1]].annotation)
        if sub is None:
            out.setdefault(res.path, name)
            continue
        try:
            data = json.loads(environ[name])
        except ValueError:
            continue
        if isinstance(data, Mapping):
            for leaf in _file_paths(sub, data, res.path):
                out.setdefault(leaf, name)
    return out


def effective_config(
    settings: Settings,
    environ: Mapping[str, str] | None = None,
    ui_overrides: Mapping[str, str] | None = None,
) -> list[ConfigEntry]:
    """Every leaf setting with its masked value and where it came from.

    ``ui_overrides`` maps dotted paths that a runtime overlay replaced (``settings`` must already include them) to the
    overlay's name. Precedence matches the loader: UI overlay > environment > config file > default.
    """
    env = os.environ if environ is None else environ
    env_paths = _env_paths(env)
    file_path, _ = config_file_path()
    file_data = load_config_file() if file_path is not None and file_path.is_file() else {}
    from_file = set(_file_paths(Settings, file_data, ()))
    overrides = dict(ui_overrides or {})
    entries: list[ConfigEntry] = []
    for path, value, default in _leaves(settings):
        dotted = ".".join(path)
        source: Source = "default"
        origin: str | None = None
        if dotted in overrides:
            source, origin = "ui", overrides[dotted]
        elif path in env_paths:
            source, origin = "env", env_paths[path]
        elif path in from_file:
            source, origin = "file", str(file_path)
        entries.append(
            ConfigEntry(
                dotted,
                display_value(path[-1], value),
                source,
                origin,
                default=_same(value, default),
            )
        )
    return entries


def _same(value: Any, default: Any) -> bool:
    try:
        return bool(to_jsonable_python(value, fallback=str) == to_jsonable_python(default, fallback=str))
    except Exception:  # pragma: no cover - defensive: an exotic default just counts as changed
        return False


def config_file_status() -> str:
    """One line describing which config file was read."""
    path, explicit = config_file_path()
    if path is None:
        return f"none ({CONFIG_ENV} is empty: environment variables and defaults only)"
    how = f"{CONFIG_ENV}={path}" if explicit else f"{CONFIG_ENV} unset, default ./{path}"
    if path.is_file():
        return f"{path.resolve()} (loaded; {how})"
    if path.is_dir():
        return f"{path} is a directory - NOT loaded ({how})"
    return f"{path} not found - NOT loaded ({how})" if explicit else f"none ({how} not found)"


def startup_summary(settings: Settings) -> str:
    """The one-line INFO logged by ``tokiwa serve``: config file, data_dir, database and LLM provider (masked)."""
    db = display_value("url", settings.database.url)
    return (
        f"config: file={config_file_status()} env={settings.env} data_dir={Path(settings.server.data_dir)} "
        f"database={db} llm.provider={settings.llm.provider}"
    )
