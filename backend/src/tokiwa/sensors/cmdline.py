"""Mask secrets passed on a process command line before it leaves the host (audit #70).

Why a separate masker: ``tokiwa.llm.redact.redact_text`` only knows ``keyword=value`` / ``keyword: value`` and
vendor token shapes. Command lines pass secrets as *separate arguments* (``--db-password X``), attached short
options (``mysql -pX``), ``user:pass`` option values (``curl -u admin:X``) and environment assignments
(``ARTEX_KEY=X ./run``). Those reached the server, the UI and the Copilot (LLM) unmasked.

What is masked (the value only; the option name stays so an analyst still sees *that* a secret was passed):

* long options whose name says "secret": ``--password X``, ``--db-password=X``, ``--api-key X``, ``--token X``,
  ``--requirepass X``, ``--passphrase X`` ... (see :data:`_SECRET_WORDS`). Options naming a *reference* to a
  secret (``--password-file``, ``--token-env``, ``--auth-url`` ...) are left alone, and so are values that look
  like a path (``/run/secrets/x``) — paths are what detection needs;
* program-specific short options, only for that program (``-p`` means *port* for ssh/nc/docker):
  ``mysql``-family ``-pX`` (attached only — ``mysql -p db`` prompts and ``db`` is the database), ``sshpass -p``,
  ``redis-cli -a``, ``mongosh -p``, ``openssl -k``, ``curl -u user:pass`` (password part), ``smbclient -U
  user%pass`` (password part);
* environment assignments ``NAME=value`` whose name ends in KEY / TOKEN / SECRET / PASS... (``ARTEX_KEY=X``,
  ``-e STRIPE_KEY=X``), and openssl's ``pass:X`` password sources;
* URL credentials with an empty user (``redis://:X@host``; ``user:pass@`` is already handled by ``redact_text``).

Never masked: the program (first token, or a token naming a known program such as ``ssh`` after ``sshpass -p X``),
option names, and path-like values. The result is idempotent (masking a masked line returns it unchanged).

Not covered (deliberately, to keep false positives low): scheme-less ``user:pass@host`` (impacket style — clashes
with ``image:tag@sha256:``), positional passwords (``htpasswd -b f user pw``, ``sqlplus u/p@db``), single-dash
long options (``keytool -storepass``), ``xfreerdp /p:``. ``redact_text`` still runs afterwards.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise

MASK = "[REDACTED:secret]"
_URL_MASK = "[REDACTED:cred]"

# Words (after splitting an option name on - _ .) that mark its value as a secret.
_SECRET_WORDS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "pass",
        "pwd",
        "secret",
        "token",
        "apikey",
        "requirepass",
        "masterauth",
        "auth",
        "authorization",
        "credential",
        "credentials",
        "bearer",
    }
)
_SECRET_PAIRS = frozenset({("api", "key"), ("access", "key"), ("secret", "key")})
# Last word of the option name that makes it a reference / setting rather than the secret itself.
_REFERENCE_WORDS = frozenset(
    {
        "file",
        "path",
        "dir",
        "directory",
        "env",
        "fd",
        "stdin",
        "cmd",
        "command",
        "url",
        "uri",
        "type",
        "method",
        "mode",
        "length",
        "len",
        "min",
        "max",
        "policy",
        "prompt",
        "helper",
        "source",
        "store",
        "plugin",
        "endpoint",
        "server",
        "host",
        "port",
        "user",
        "username",
        "name",
        "id",
        "header",
        "required",
        "expiry",
        "expires",
        "ttl",
        "timeout",
        "lifetime",
        "interval",
        "retries",
        "provider",
        "format",
        "mechanism",
    }
)
_ENV_SECRET_SUFFIXES = frozenset(
    {
        "KEY",
        "APIKEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "PASS",
        "PWD",
        "PASSPHRASE",
        "AUTH",
        "CREDENTIALS",
    }
)
_ENV_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.+)$", re.S)
_EMPTY_USER_URL = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://):([^/\s@]+)@")
_PATH_PREFIXES = ("/", "./", "../", "~/")
_QUOTES = "'\""


@dataclass(frozen=True)
class _Rule:
    """Program-specific short options. ``value``: next token or attached; ``attached``: attached value only;
    ``userpass``: value is ``user<delim>pass`` and only the part after the delimiter is secret."""

    value: frozenset[str] = frozenset()
    attached: frozenset[str] = frozenset()
    userpass: frozenset[str] = frozenset()
    delim: str = ":"
    names: frozenset[str] = frozenset()
    # A wrapper (``sshpass``) runs another command: its first positional argument starts a new program.
    wrapper: bool = False


_MYSQL = _Rule(
    names=frozenset(
        {
            "mysql",
            "mariadb",
            "mysqldump",
            "mysqladmin",
            "mysqlimport",
            "mysqlshow",
            "mysqlcheck",
            "mysqlslap",
            "mysqlbinlog",
            "mysqlpump",
            "mysqlsh",
            "mariadb-dump",
            "mariadb-admin",
            "mariadb-import",
            "mariadb-show",
            "mariadb-check",
            "mariadb-binlog",
        }
    ),
    attached=frozenset({"-p"}),
)
_RULES: tuple[_Rule, ...] = (
    _MYSQL,
    _Rule(names=frozenset({"sshpass"}), value=frozenset({"-p"}), wrapper=True),
    _Rule(names=frozenset({"redis-cli", "valkey-cli", "keydb-cli"}), value=frozenset({"-a"})),
    _Rule(
        names=frozenset(
            {
                "mongo",
                "mongosh",
                "mongodump",
                "mongorestore",
                "mongoexport",
                "mongoimport",
                "mongostat",
                "mongotop",
                "mongofiles",
            }
        ),
        value=frozenset({"-p"}),
    ),
    _Rule(names=frozenset({"openssl"}), value=frozenset({"-k"})),
    _Rule(names=frozenset({"curl"}), userpass=frozenset({"-u", "--user", "-U", "--proxy-user"}), delim=":"),
    _Rule(
        names=frozenset({"smbclient", "rpcclient", "smbcacls", "smbget", "smbtree", "net", "winexe"}),
        userpass=frozenset({"-U", "--user"}),
        delim="%",
    ),
)
_BY_NAME: dict[str, _Rule] = {name: r for r in _RULES for name in r.names}
_EMPTY_RULE = _Rule()


def _program(token: str) -> str:
    name = token.strip(_QUOTES).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _is_secret_option(name: str) -> bool:
    """``name`` without leading dashes, e.g. ``db-password``."""
    words = [w for w in re.split(r"[-_.]+", name.lower()) if w]
    if not words or words[0] == "no" or words[-1] in _REFERENCE_WORDS:
        return False
    if any(w in _SECRET_WORDS for w in words):
        return True
    return any(pair in _SECRET_PAIRS for pair in pairwise(words))


def _maskable(value: str) -> bool:
    v = value.strip(_QUOTES)
    return bool(v) and not v.startswith(MASK[:10]) and not v.startswith(_PATH_PREFIXES)


def _mask_userpass(value: str, delim: str) -> str:
    quote = value[0] if value[:1] in _QUOTES else ""
    user, sep, secret = value.strip(_QUOTES).partition(delim)
    if not sep or not secret or secret.startswith(MASK[:10]):
        return value
    return f"{quote}{user}{delim}{MASK}{quote}"


def _mask_env(token: str) -> str | None:
    m = _ENV_ASSIGN.match(token.strip(_QUOTES))
    if m is None:
        return None
    name = m.group(1).upper()
    last = name.rsplit("_", 1)[-1]
    if last in _ENV_SECRET_SUFFIXES or any(w in name for w in ("PASSWORD", "SECRET", "TOKEN", "APIKEY")):
        return token if m.group(2).startswith(MASK[:10]) else f"{m.group(1)}={MASK}"
    return None


def mask_argv(argv: Sequence[str] | str) -> str:
    """Return the command line as one string (argv joined by spaces) with argument secrets masked."""
    line = " ".join(str(a) for a in argv) if not isinstance(argv, str) else argv
    if not line:
        return line
    parts = re.split(r"(\s+)", line)
    tokens = parts[0::2]
    rule = _EMPTY_RULE
    mask_next: str | None = None  # "value" | "userpass:<delim>"
    first = True
    for i, tok in enumerate(tokens):
        if not tok:
            continue
        core = tok.strip(_QUOTES)
        if first:
            env = _mask_env(tok)  # ``ARTEX_KEY=X ./run`` written as one string
            if env is not None:
                tokens[i] = env
                continue
            first = False
            rule = _BY_NAME.get(_program(tok), _EMPTY_RULE)
            continue
        if mask_next is not None:
            pending, mask_next = mask_next, None
            if not core.startswith("-"):
                if pending == "value":
                    if _maskable(tok):
                        tokens[i] = MASK
                else:
                    tokens[i] = _mask_userpass(tok, pending.split(":", 1)[1])
                continue
        prog = _BY_NAME.get(_program(tok))
        if not core.startswith("-") and (prog is not None or rule.wrapper):
            rule = prog or _EMPTY_RULE  # ``sshpass -p X ssh -p 2222``: ssh's -p is a port again
            continue
        if core.startswith("-") and len(core) > 1:
            name, eq, value = core.partition("=")
            short = name[:2] if not name.startswith("--") else name
            if name in rule.userpass:
                if eq:
                    tokens[i] = f"{name}={_mask_userpass(value, rule.delim)}"
                else:
                    mask_next = f"userpass:{rule.delim}"
                continue
            if not name.startswith("--") and short in rule.userpass and len(name) > 2:
                tokens[i] = f"{short}{_mask_userpass(core[2:], rule.delim)}"
                continue
            if not name.startswith("--") and (short in rule.value or short in rule.attached):
                attached = core[2:]
                if attached:
                    if not attached.startswith(MASK[:10]):
                        tokens[i] = f"{short}{MASK}"
                elif short in rule.value:
                    mask_next = "value"
                continue
            if name.startswith("--") and _is_secret_option(name.lstrip("-")):
                if eq:
                    if value and _maskable(value):
                        tokens[i] = f"{name}={MASK}"
                else:
                    mask_next = "value"
                continue
            continue
        env = _mask_env(tok)
        if env is not None:
            tokens[i] = env
            continue
        if core.startswith("pass:") and len(core) > 5 and not core[5:].startswith(MASK[:10]):
            tokens[i] = f"pass:{MASK}"  # openssl -passin pass:X
    parts[0::2] = tokens
    out = "".join(parts)
    return _EMPTY_USER_URL.sub(lambda m: f"{m.group(1)}{_URL_MASK}@", out)
